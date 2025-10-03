import { expect } from "chai";
import { solana_program_init, Keypair } from "crate";
solana_program_init();

const KEYPAIR_LEN = 64;

describe("Keypair", function () {
  it("works", () => {
    const keypair = new Keypair();
    let bytes = keypair.toBytes();
    expect(bytes).to.have.length(64);

    const recoveredKeypair = Keypair.fromBytes(bytes);
    expect(keypair.pubkey().equals(recoveredKeypair.pubkey()));
  });

  it("input length validation", () => {
    expect(() => {
      Keypair.fromBytes(new Uint8Array(KEYPAIR_LEN + 1));
    }).to.throw(/Invalid length for Keypair bytes/);

    expect(() => {
        Keypair.fromBytes(new Uint8Array(KEYPAIR_LEN - 1));
      }).to.throw(/Invalid length for Keypair bytes/);
  })
});
