// Make coprocessors circuit from Circom

use std::{error::Error, fs::File, io::BufReader, marker::PhantomData, path::PathBuf};
use ark_ec::CurveGroup;
use num_bigint::BigInt;

use ark_circom::{circom::r1cs_reader, WitnessCalculator};
use ark_ff::PrimeField;

use nexus_nova::r1cs::R1CSShape;
use nexus_nova::ccs::SparseMatrix;

pub type Constraints<G> = (ConstraintVec<G>, ConstraintVec<G>, ConstraintVec<G>);
pub type ConstraintVec<G> = Vec<(usize, G)>;

type ExtractedConstraints<G> = (Vec<Constraints<G>>, usize, usize);
pub type ExtractedConstraintsResult<F> = Result<ExtractedConstraints<F>, Box<dyn Error>>;

pub struct CircomWrapper<G: CurveGroup> {
    r1cs_filepath: PathBuf,
    wasm_filepath: PathBuf,
    _marker: PhantomData<G>,
}

impl<G: CurveGroup> CircomWrapper<G> {
    // Creates a new instance of the CircomWrapper with the file paths.
    pub fn new(r1cs_filepath: PathBuf, wasm_filepath: PathBuf) -> Self {
        CircomWrapper {
            r1cs_filepath,
            wasm_filepath,
            _marker: PhantomData,
        }
    }

    // TODO: Split into witness and instance, not entire Z
    // Aggregates multiple functions to obtain R1CS and Z as defined in nexus from Circom.
    pub fn extract_r1cs_and_z(
        &self,
        inputs: &[(String, Vec<BigInt>)],
    ) -> Result<(R1CSShape<G>, Vec<G::ScalarField>), Box<dyn Error>> {
        let (constraints, pub_io_len, num_variables) = self.extract_constraints_from_r1cs()?;
        let witness = self.calculate_witness(inputs)?;
        self.circom_to_folding_schemes_r1cs_and_z(constraints, &witness, pub_io_len, num_variables)
    }

    // Extracts constraints from the r1cs file.
    pub fn extract_constraints_from_r1cs(&self) -> ExtractedConstraintsResult<G::ScalarField> {
        let file = File::open(&self.r1cs_filepath)?;
        let reader = BufReader::new(file);
        let r1cs_file = r1cs_reader::R1CSFile::<G::ScalarField>::new(reader)?;
        let pub_io_len = (r1cs_file.header.n_pub_in + r1cs_file.header.n_pub_out) as usize;
        let r1cs = r1cs_reader::R1CS::<G::ScalarField>::from(r1cs_file);
        let num_variables = r1cs.num_variables;
    
        let constraints: Vec<Constraints<G::ScalarField>> = r1cs.constraints;
    
        Ok((constraints, pub_io_len, num_variables))
    }
    
    // Converts a set of constraints from ark-circom into R1CS format of nexus.
    pub fn convert_to_folding_schemes_r1cs(
        &self,
        constraints: Vec<Constraints<G::ScalarField>>,
        pub_io_len: usize,
        num_variables: usize,
    ) -> R1CSShape<G> {
        let mut a_data = Vec::new();
        let mut b_data = Vec::new();
        let mut c_data = Vec::new();

        // Collect all data entries from each vector of matrices
        for (a_vec, b_vec, c_vec) in &constraints {
            a_data.extend(a_vec.iter().map(|&(index, coeff)| (coeff, index)));
            b_data.extend(b_vec.iter().map(|&(index, coeff)| (coeff, index)));
            c_data.extend(c_vec.iter().map(|&(index, coeff)| (coeff, index)));
        }

        // Create SparseMatrix for A, B, C
        let a_matrix = SparseMatrix::new(&[a_data], constraints.len(), num_variables);
        let b_matrix = SparseMatrix::new(&[b_data], constraints.len(), num_variables);
        let c_matrix = SparseMatrix::new(&[c_data], constraints.len(), num_variables);

        R1CSShape {
            num_constraints: constraints.len(),
            // TODO: check
            num_vars: num_variables - pub_io_len,
            num_io: pub_io_len,
            A: a_matrix,
            B: b_matrix,
            C: c_matrix,
        }
    }
    
    pub fn calculate_witness(&self, inputs: &[(String, Vec<BigInt>)]) -> Result<Vec<BigInt>, Box<dyn Error>> {
        let mut calculator = WitnessCalculator::new(&self.wasm_filepath)?;
        Ok(calculator.calculate_witness(inputs.iter().cloned(), true)?)
    }

    // Converts a num_bigint input to `PrimeField`'s BigInt.
    pub fn num_bigint_to_ark_bigint<F: PrimeField>(
        &self,
        value: &BigInt,
    ) -> Result<F::BigInt, Box<dyn Error>> {
        let big_uint = value
            .to_biguint()
            .ok_or_else(|| "BigInt is negative".to_string())?;
        F::BigInt::try_from(big_uint).map_err(|_| "BigInt conversion failed".to_string().into())
    }

    // Converts R1CS constraints and witness from ark-circom format into nexus R1CS and z format.
    pub fn circom_to_folding_schemes_r1cs_and_z(
        &self,
        constraints: Vec<Constraints<G::ScalarField>>,
        witness: &[BigInt],
        pub_io_len: usize,
        num_variables: usize,
    ) -> Result<(R1CSShape<G>, Vec<G::ScalarField>), Box<dyn Error>> {
        let folding_schemes_r1cs = self.convert_to_folding_schemes_r1cs(constraints, pub_io_len, num_variables);

        let z: Result<Vec<G::ScalarField>, _> = witness
            .iter()
            .map(|big_int| {
                let ark_big_int = self.num_bigint_to_ark_bigint::<G::ScalarField>(big_int)?;
                G::ScalarField::from_bigint(ark_big_int).ok_or_else(|| {
                    "Failed to convert bigint to field element".to_string().into()
                })
            })
            .collect();

        z.map(|z| (folding_schemes_r1cs, z))
    }
}

#[cfg(test)]
mod tests {
    use crate::CircomWrapper;
    use num_bigint::BigInt;
    use std::env;   
    use ark_test_curves::bls12_381::{G1Projective as G};

    fn test_circom_conversion_logic(expect_success: bool, inputs: Vec<(String, Vec<BigInt>)>) {
        let current_dir = env::current_dir().unwrap();
        
        // TODO: Change path
        let base_path = current_dir.join("src/frontend/circom/test_folder");

        let r1cs_filepath = base_path.join("test_circuit.r1cs");
        let wasm_filepath = base_path.join("test_circuit_js/test_circuit.wasm");

        assert!(r1cs_filepath.exists());
        assert!(wasm_filepath.exists());

        let circom_wrapper = CircomWrapper::<G>::new(r1cs_filepath, wasm_filepath);

        let (r1cs, z) = circom_wrapper
            .extract_r1cs_and_z(&inputs)
            .expect("Error processing input");

        // TODO: Change is_satisfied function of nexus
        // Checks the relationship of R1CS.
        let check_result = std::panic::catch_unwind(|| {
            // r1cs.check_relation(&z).unwrap();
        });

        match (expect_success, check_result) {
            (true, Ok(_)) => {}
            (false, Err(_)) => {}
            (true, Err(_)) => panic!("Expected success but got a failure."),
            (false, Ok(_)) => panic!("Expected a failure but got success."),
        }
    }

    #[test]
    fn test_circom_conversion() {
        // expect it to pass for correct inputs.
        test_circom_conversion_logic(true, vec![("step_in".to_string(), vec![BigInt::from(3)])]);

        // expect it to fail for incorrect inputs.
        test_circom_conversion_logic(false, vec![("step_in".to_string(), vec![BigInt::from(7)])]);
    }
}