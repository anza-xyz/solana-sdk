import { expect } from "chai";
import {
  solana_program_init,
  AccountMeta,
  Address,
  Keypair,
  Hash,
  Instruction,
  Transaction,
} from "crate";
solana_program_init();

const MAX_TRANSACTION_SIZE = 1232;

describe("Transaction", function () {
  it("Instruction", () => {
    const payer = Keypair.fromBytes(
      new Uint8Array([
        241, 230, 222, 64, 184, 48, 232, 92, 156, 210, 229, 183, 154, 251, 5,
        227, 98, 184, 34, 234, 39, 106, 62, 210, 166, 187, 31, 44, 40, 96, 24,
        51, 252, 28, 2, 120, 234, 212, 139, 111, 96, 8, 168, 204, 34, 72, 199,
        205, 117, 165, 82, 51, 32, 93, 211, 36, 239, 245, 139, 218, 99, 211,
        207, 177,
      ])
    );

    const src = Keypair.fromBytes(
      new Uint8Array([
        172, 219, 139, 103, 154, 105, 92, 23, 227, 108, 174, 80, 215, 227, 62,
        8, 66, 38, 151, 239, 148, 184, 180, 148, 149, 18, 106, 94, 73, 143, 27,
        132, 193, 64, 199, 93, 222, 83, 172, 224, 116, 205, 54, 38, 191, 178,
        149, 71, 65, 132, 46, 71, 126, 81, 63, 254, 21, 101, 90, 52, 67, 204,
        128, 199,
      ])
    );

    const programId = new Address("11111111111111111111111111111111");
    const dst = new Address("11111111111111111111111111111112");
    const instructionData = new Uint8Array([2, 0, 0, 0, 123, 0, 0, 0, 0, 0, 0, 0]);

    const recentBlockhash = new Hash(
      "EETubP5AKHgjPAhzPAFcb8BAY1hMH639CWCFTqi3hq1k"
    );

    let instructions = [];
    let instruction = new Instruction(programId);
    instruction.setData(instructionData);
    instruction.addAccount(AccountMeta.newWritable(src.pubkey(), true))
    instruction.addAccount(AccountMeta.newWritable(dst, false))
    instructions.push(instruction);

    let transaction = new Transaction(instructions, payer.pubkey());
    transaction.partialSign(payer, recentBlockhash);
    transaction.partialSign(src, recentBlockhash);
    expect(transaction.isSigned()).to.be.true;
    transaction.verify();

    expect(Buffer.from(transaction.toBytes()).toString("base64")).to.equal(
      "AoZrVzP93eyp3vbl6CU9XQjQfm4Xp/7nSiBlsX/kJmfTQZsGTOrFnt6EUqHVte97fGZ71UAXDfLbR5B31OtRdgdab57BOU8mq0ztMutZAVBPtGJHVly8RPz4TYa+OFU7EIk3Wrv4WUMCb/NR+LxELLH+tQt5SrkvB7rCE2DniM8JAgABBPwcAnjq1ItvYAiozCJIx811pVIzIF3TJO/1i9pj08+xwUDHXd5TrOB0zTYmv7KVR0GELkd+UT/+FWVaNEPMgMcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxJrndgN4IFTxep3s6kO0ROug7bEsbx0xxuDkqEvwUusBAwIBAgwCAAAAewAAAAAAAAA="
    );
  });

  it("input length validation", () => {
    const oversizedTxBytes = new Uint8Array(MAX_TRANSACTION_SIZE + 1);
    expect(() => {
      Transaction.fromBytes(oversizedTxBytes);
    }).to.throw(/Transaction size too large/);
  });
});
