use bitcoin::{
    absolute::LockTime,
    consensus::Encodable,
    key::TapTweak,
    secp256k1::{self, Secp256k1, Verification, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
    taproot::Signature,
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, TapNodeHash, TapSighash, TapSighashType, Transaction,
    TxIn, TxOut, Witness,
};

use std::sync::LazyLock;

/// A dummy Schnorr signature.
static DUMMY_SIGNATURE: LazyLock<Signature> = LazyLock::new(|| Signature {
    signature: secp256k1::schnorr::Signature::from_slice(&[0; 64]).unwrap(),
    sighash_type: TapSighashType::All,
});

/// An error type that wraps the various bitcoin related arrors which we may encounter
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An IO error was returned from the [`bitcoin`] library. This is usually an
    /// error that occurred during encoding/decoding of bitcoin types.
    #[error("an io error was returned from the bitcoin library: {0}")]
    BitcoinIo(#[source] bitcoin::io::Error),
    /// An error was returned from the bitcoinconsensus library.
    #[error("error returned from libbitcoinconsensus: {0}")]
    BitcoinConsensus(bitcoinconsensus::Error),
    /// Taproot error
    #[error("an error occurred when constructing the taproot signing digest: {0}")]
    Taproot(#[from] bitcoin::sighash::TaprootError),
}

/// An unspent transaction output, which contains all of the information needed to identify or spend
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Utxo {
    /// The outpoint of the signers' UTXO
    pub outpoint: OutPoint,
    /// The amount associated with the above UTXO
    pub amount: u64,
    /// The public key used to create the key-spend only taproot script.
    pub public_key: XOnlyPublicKey,
}

impl Utxo {
    /// Create a TxIn object for the signers' UTXO
    ///
    /// The signers' UTXO is always a key-spend only taproot UTXO, so a
    /// valid signature is all that is needed to spend it.
    fn as_tx_input(&self, signature: &Signature) -> TxIn {
        TxIn {
            previous_output: self.outpoint,
            sequence: Sequence::ZERO,
            witness: Witness::p2tr_key_spend(signature),
            script_sig: ScriptBuf::new(),
        }
    }

    /// Construct the UTXO associated with this outpoint.
    fn as_tx_output<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        merkle_root: Option<TapNodeHash>,
    ) -> TxOut {
        Self::new_tx_output(secp, self.public_key, self.amount, merkle_root)
    }

    /// Construct the new signers' UTXO
    ///
    /// The signers' UTXO is always a key-spend only taproot UTXO.
    fn new_tx_output<C: Verification>(
        secp: &Secp256k1<C>,
        public_key: XOnlyPublicKey,
        sats: u64,
        merkle_root: Option<TapNodeHash>,
    ) -> TxOut {
        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::new_p2tr(secp, public_key, merkle_root),
        }
    }
}

/// A transaction which we will use to see if we can construct a valid signature
pub struct UnsignedTx {
    /// utxo
    pub utxo: Utxo,
    /// tx
    pub tx: Transaction,
}

impl UnsignedTx {
    const AMOUNT: u64 = 0;

    /// Construct an unsigned mock transaction.
    ///
    /// This will use the provided `aggregate_key` to construct
    /// a [`Transaction`] with a single input and output with value 0.
    pub fn new(signer_public_key: XOnlyPublicKey) -> Self {
        let utxo = Utxo {
            outpoint: OutPoint::null(),
            amount: Self::AMOUNT,
            public_key: signer_public_key,
        };

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![utxo.as_tx_input(&DUMMY_SIGNATURE)],
            output: vec![TxOut {
                value: Amount::from_sat(Self::AMOUNT),
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
        };

        Self { tx, utxo }
    }

    /// Gets the sighash for the signers' input UTXO which needs to be signed
    /// before the transaction can be broadcast.
    pub fn compute_sighash<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        merkle_root: Option<TapNodeHash>,
    ) -> Result<TapSighash, Error> {
        let prevouts = [self.utxo.as_tx_output(secp, merkle_root)];
        let mut sighasher = SighashCache::new(&self.tx);

        sighasher
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::All)
            .map_err(Into::into)
    }

    /// Tests if the provided taproot [`Signature`] is valid for spending the
    /// signers' UTXO. This function will return  [`Error::BitcoinConsensus`]
    /// error if the signature fails verification, passing the underlying error
    /// from [`bitcoinconsensus`].
    pub fn verify_signature<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        signature: &Signature,
        merkle_root: Option<TapNodeHash>,
    ) -> Result<(), Error> {
        // Create a copy of the transaction so that we don't modify the
        // transaction stored in the struct.
        let mut tx = self.tx.clone();

        // Set the witness data on the input from the provided signature.
        tx.input[0].witness = Witness::p2tr_key_spend(signature);

        // Encode the transaction to bytes (needed by the bitcoinconsensus
        // library).
        let mut tx_bytes: Vec<u8> = Vec::new();
        tx.consensus_encode(&mut tx_bytes)
            .map_err(Error::BitcoinIo)?;

        // Get the prevout for the signers' UTXO.
        let prevout = self.utxo.as_tx_output(secp, merkle_root);
        let prevout_script_bytes = prevout.script_pubkey.as_script().as_bytes();

        // Create the bitcoinconsensus UTXO object.
        let prevout_utxo = bitcoinconsensus::Utxo {
            script_pubkey: prevout_script_bytes.as_ptr(),
            script_pubkey_len: prevout_script_bytes.len() as u32,
            value: Self::AMOUNT as i64,
        };

        // We specify the flags to include all pre-taproot and taproot
        // verifications explicitly.
        // https://github.com/rust-bitcoin/rust-bitcoinconsensus/blob/master/src/lib.rs
        let flags = bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT | bitcoinconsensus::VERIFY_TAPROOT;

        // Verify that the transaction updated with the provided signature can
        // successfully spend the signers' UTXO. Note that the amount is not
        // used in the verification process for taproot spends, only the
        // signature.
        bitcoinconsensus::verify_with_flags(
            prevout_script_bytes,
            Self::AMOUNT,
            &tx_bytes,
            Some(&[prevout_utxo]),
            0,
            flags,
        )
        .map_err(Error::BitcoinConsensus)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        compute,
        taproot::{test_helpers, SchnorrProof},
        traits::{Aggregator, Signer},
        v2,
    };

    use rand_core::OsRng;

    #[test]
    fn verify_sig_no_merkle_root() {
        verify_sig(None)
    }

    #[test]
    fn verify_sig_some_merkle_root() {
        verify_sig(Some([0u8; 32]));
    }

    fn verify_sig(raw_merkle_root: Option<[u8; 32]>) {
        let merkle_root = match raw_merkle_root {
            Some(hash) => Some(TapNodeHash::assume_hidden(hash)),
            None => None,
        };
        let secp = Secp256k1::new();

        // Generate a key pair which will serve as the signers' aggregate key.
        let secret_key = secp256k1::SecretKey::new(&mut OsRng);
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let tweaked = keypair.tap_tweak(&secp, merkle_root);
        let (aggregate_key, _) = keypair.x_only_public_key();

        // Create a new transaction using the aggregate key.
        let unsigned = UnsignedTx::new(aggregate_key);

        let tapsig = unsigned
            .compute_sighash(&secp, merkle_root)
            .expect("failed to compute taproot sighash");

        // Sign the taproot sighash.
        let message = secp256k1::Message::from_digest_slice(tapsig.as_ref())
            .expect("Failed to create message");

        // first test a standard schnorr signature

        // [1] Verify the correct signature, which should succeed.
        let schnorr_sig = secp.sign_schnorr(&message, &tweaked.to_keypair());
        let taproot_sig = bitcoin::taproot::Signature {
            signature: schnorr_sig,
            sighash_type: TapSighashType::All,
        };
        unsigned
            .verify_signature(&secp, &taproot_sig, merkle_root)
            .expect("signature verification failed");

        // [2] Verify the correct signature, but with a different sighash type,
        // which should fail.
        let taproot_sig = bitcoin::taproot::Signature {
            signature: schnorr_sig,
            sighash_type: TapSighashType::None,
        };
        unsigned
            .verify_signature(&secp, &taproot_sig, merkle_root)
            .expect_err("signature verification should have failed");

        // [3] Verify an incorrect signature with the correct sighash type,
        // which should fail. In this case we've created the signature using
        // the untweaked keypair.
        let schnorr_sig = secp.sign_schnorr(&message, &keypair);
        let taproot_sig = bitcoin::taproot::Signature {
            signature: schnorr_sig,
            sighash_type: TapSighashType::All,
        };
        unsigned
            .verify_signature(&secp, &taproot_sig, merkle_root)
            .expect_err("signature verification should have failed");

        // [4] Verify an incorrect signature with the correct sighash type, which
        // should fail. In this case we use a completely newly generated keypair.
        let secret_key = secp256k1::SecretKey::new(&mut OsRng);
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let schnorr_sig = secp.sign_schnorr(&message, &keypair);
        let taproot_sig = bitcoin::taproot::Signature {
            signature: schnorr_sig,
            sighash_type: TapSighashType::All,
        };
        unsigned
            .verify_signature(&secp, &taproot_sig, merkle_root)
            .expect_err("signature verification should have failed");

        // [5] Same as [4], but using its tweaked key.
        let tweaked = keypair.tap_tweak(&secp, merkle_root);
        let schnorr_sig = secp.sign_schnorr(&message, &tweaked.to_keypair());
        let taproot_sig = bitcoin::taproot::Signature {
            signature: schnorr_sig,
            sighash_type: TapSighashType::All,
        };
        unsigned
            .verify_signature(&secp, &taproot_sig, merkle_root)
            .expect_err("signature verification should have failed");

        // now test a WSTS signature

        // Generate a DKG aggregate key.
        let num_keys: u32 = 10;
        let num_parties: u32 = 4;
        let threshold: u32 = 7;
        let signer_ids: Vec<Vec<u32>> = [
            [1, 2, 3].to_vec(),
            [4, 5].to_vec(),
            [6, 7, 8].to_vec(),
            [9, 10].to_vec(),
        ]
        .to_vec();
        let mut signers: Vec<v2::Signer> = signer_ids
            .iter()
            .enumerate()
            .map(|(id, ids)| {
                v2::Signer::new(
                    id.try_into().unwrap(),
                    ids,
                    num_parties,
                    num_keys,
                    threshold,
                    &mut OsRng,
                )
            })
            .collect();

        let polys = match test_helpers::dkg(&mut signers, &mut OsRng) {
            Ok(polys) => polys,
            Err(secret_errors) => {
                panic!("Got secret errors from DKG: {secret_errors:?}");
            }
        };

        let mut signing_set = [signers[0].clone(), signers[1].clone(), signers[3].clone()].to_vec();
        let key_ids = signing_set
            .iter()
            .flat_map(|s| s.get_key_ids())
            .collect::<Vec<u32>>();
        let mut sig_agg = v2::Aggregator::new(num_keys, threshold);
        sig_agg.init(&polys).expect("aggregator init failed");
        let tweaked_public_key = compute::tweaked_public_key(&sig_agg.poly[0], raw_merkle_root);
        // taproot code within both wsts and libsecp256k1 will take care of tweaking the key
        let aggregate_key = XOnlyPublicKey::from_slice(&sig_agg.poly[0].x().to_bytes())
            .expect("failed to make XOnlyPublicKey");

        // Create a new transaction using the aggregate key.
        let unsigned = UnsignedTx::new(aggregate_key);

        let tapsig = unsigned
            .compute_sighash(&secp, merkle_root)
            .expect("failed to compute taproot sighash");

        // Sign the taproot sighash.
        let msg: &[u8] = tapsig.as_ref();
        let (nonces, sig_shares) =
            test_helpers::sign(msg, &mut signing_set, &mut OsRng, raw_merkle_root);
        let proof = match sig_agg.sign_taproot(msg, &nonces, &sig_shares, &key_ids, raw_merkle_root)
        {
            Err(e) => panic!("Aggregator sign failed: {e:?}"),
            Ok(proof) => proof,
        };
        // now ser/de the proof
        let proof_bytes = proof.to_bytes();
        let proof_deser = SchnorrProof::from(proof_bytes);

        assert_eq!(proof, proof_deser);
        assert!(proof_deser.verify(&tweaked_public_key.x(), msg));

        // [1] Verify the correct signature, which should succeed.
        let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&proof_bytes)
            .expect("Failed to parse Signature from slice");
        let taproot_sig = bitcoin::taproot::Signature {
            signature: schnorr_sig,
            sighash_type: TapSighashType::All,
        };
        unsigned
            .verify_signature(&secp, &taproot_sig, merkle_root)
            .expect("signature verification failed");

        // [2] Verify the correct signature, but with a different sighash type,
        // which should fail.
        let taproot_sig = bitcoin::taproot::Signature {
            signature: schnorr_sig,
            sighash_type: TapSighashType::None,
        };
        unsigned
            .verify_signature(&secp, &taproot_sig, merkle_root)
            .expect_err("signature verification should have failed");
    }
}
