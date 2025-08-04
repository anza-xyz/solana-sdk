import { expect } from "chai";
import {
  solana_program_init,
  Address,
  Keypair,
  Hash,
  MyProgramInstruction,
  Transaction,
} from "crate";
solana_program_init();

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

    const programId = new Address("11111111111111111111111111111111");
    const recentBlockhash = new Hash(
      "EETubP5AKHgjPAhzPAFcb8BAY1hMH639CWCFTqi3hq1k"
    );

    let instructions = [];
    let instruction = new MyProgramInstruction(programId);
    instructions.push(instruction);

    let transaction = new Transaction(instructions, payer.pubkey());
    transaction.partialSign(payer, recentBlockhash);
    expect(transaction.isSigned()).to.be.true;
    transaction.verify();

    expect(Buffer.from(transaction.toBytes()).toString("base64")).to.equal(
      "AfvLzMtWBl2MvGFOE6rPZ6gjzKv7eVlNXF0wO4VDxjFXZx0AA/x05cmRHJZR8InwR4lBEwVsHSVa/uBwYSh0dQEBAAEC/BwCeOrUi29gCKjMIkjHzXWlUjMgXdMk7/WL2mPTz7EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMSa53YDeCBU8Xqd7OpDtETroO2xLG8dMcbg5KhL8FLrAQEAAA=="
    );
  });
});
