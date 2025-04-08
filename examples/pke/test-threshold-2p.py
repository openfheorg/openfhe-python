from openfhe import *


def main():
    mult_depth = 1
    scale_mod_size = 50
    batch_size = 16
    sertype = BINARY

    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(mult_depth)
    parameters.SetScalingModSize(scale_mod_size)
    parameters.SetBatchSize(batch_size)

    cc = GenCryptoContext(parameters)
    cc.Enable(PKE)
    cc.Enable(KEYSWITCH)
    cc.Enable(LEVELEDSHE)
    cc.Enable(ADVANCEDSHE)
    cc.Enable(MULTIPARTY)  


    '''
    Say we have 2 parties: p1 (lead) and p2. 
    IMPORTANT: Any communication between the 2 has to be serialized.
    '''

    '''We set the same CryptoContext'''
    # Party 1
    cc_p1 = cc
    cc_to_share = Serialize(cc_p1, sertype)  # Send cc_to_share to Party 2
    
    # Party 2
    cc_p2 = DeserializeCryptoContextString(cc_to_share, sertype) # Received cc_to_share from Party 1




    '''Generating keys for each party'''
    # Party 1
    keys_p1 = cc_p1.KeyGen()
    pk_to_share = Serialize(keys_p1.publicKey, sertype)  # Send pk_to_share to Party 2

    # Party 2
    pk_received = DeserializePublicKeyString(pk_to_share, sertype) # Received pk_to_share from Party 1
    keys_p2 = cc_p2.MultipartyKeyGen(pk_received, False, True)

    mp_public_key = cc_p1.MultiAddPubKeys(keys_p1.publicKey, keys_p2.publicKey, keys_p2.publicKey.GetKeyTag())



    '''EvalSumKeys'''
    # Party 1
    cc_p1.EvalSumKeyGen(keys_p1.secretKey)
    evalSumKeys_p1 = cc_p1.GetEvalSumKeyMap(keys_p1.secretKey.GetKeyTag())
    evalSumKeys_to_share = Serialize(evalSumKeys_p1, sertype)     # Send evalSumKeys_to_share to Party 2
    testkeys = DeserializeEvalKeyMapString(evalSumKeys_to_share, sertype)
    
    # # Party 2
    evalSumKeysB = cc_p2.MultiEvalSumKeyGen(keys_p2.secretKey, DeserializeEvalKeyMapString(evalSumKeys_to_share, sertype), keys_p2.publicKey.GetKeyTag())


if __name__ == "__main__":
    main()
