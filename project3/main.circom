pragma circom 2.1.4;

include "poseidon2.circom";

template Main() {
  signal input privateInputs[2];
  signal input publicHash;
  
  component hasher = Poseidon2_2_1();
  hasher.hashInput[0] <== privateInputs[0];
  hasher.hashInput[1] <== privateInputs[1];
  
  hasher.hashOutput === publicHash;
}

component main = Main();