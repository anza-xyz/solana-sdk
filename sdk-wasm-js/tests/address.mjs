import { expect } from "chai";
import { solana_program_init, Address } from "crate";
solana_program_init();

// TODO: wasm_bindgen doesn't currently support exporting constants
const MAX_SEED_LEN = 32;
const ADDRESS_BYTES = 32;
const MAX_SEEDS = 16;

describe("Address", function () {
  it("invalid", () => {
    expect(() => {
      new Address([
        3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
      ]);
    }).to.throw();

    expect(() => {
      new Address([
        'invalid', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
      ]);
    }).to.throw();

    expect(() => {
      new Address(
        "0x300000000000000000000000000000000000000000000000000000000000000000000"
      );
    }).to.throw();

    expect(() => {
      new Address(
        "0x300000000000000000000000000000000000000000000000000000000000000"
      );
    }).to.throw();

    expect(() => {
      new Address(
        "135693854574979916511997248057056142015550763280047535983739356259273198796800000"
      );
    }).to.throw();

    expect(() => {
      new Address("12345");
    }).to.throw();
  });

  it("toString", () => {
    const key = new Address("CiDwVBFgWV9E5MvXWoLgnEgn2hK7rJikbvfWavzAQz3");
    expect(key.toString()).to.eq("CiDwVBFgWV9E5MvXWoLgnEgn2hK7rJikbvfWavzAQz3");

    const key2 = new Address("1111111111111111111111111111BukQL");
    expect(key2.toString()).to.eq("1111111111111111111111111111BukQL");

    const key3 = new Address("11111111111111111111111111111111");
    expect(key3.toString()).to.eq("11111111111111111111111111111111");

    const key4 = new Address([
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0,
    ]);
    expect(key4.toString()).to.eq("11111111111111111111111111111111");
  });

  it("toBytes", () => {
    const key = new Address("CiDwVBFgWV9E5MvXWoLgnEgn2hK7rJikbvfWavzAQz3");
    expect(key.toBytes()).to.deep.equal(
      new Uint8Array([
        3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
      ])
    );

    const key2 = new Address();
    expect(key2.toBytes()).to.deep.equal(
      new Uint8Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
      ])
    );
  });

  it("isOnCurve", () => {
    let onCurve = new Address("J4NYrSRccTUGXP7wmFwiByakqWKZb5RwpiAoskpgAQRb");
    expect(onCurve.isOnCurve()).to.be.true;

    let offCurve = new Address("12rqwuEgBYiGhBrDJStCiqEtzQpTTiZbh7teNVLuYcFA");
    expect(offCurve.isOnCurve()).to.be.false;
  });

  it("equals", () => {
    const arrayKey = new Address([
      3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0,
    ]);
    const base58Key = new Address("CiDwVBFgWV9E5MvXWoLgnEgn2hK7rJikbvfWavzAQz3");

    expect(arrayKey.equals(base58Key)).to.be.true;
  });

  it("createWithSeed", async () => {
    const defaultPublicKey = new Address("11111111111111111111111111111111");
    const derivedKey = Address.createWithSeed(
      defaultPublicKey,
      "limber chicken: 4/45",
      defaultPublicKey
    );

    expect(
      derivedKey.equals(
        new Address("9h1HyLCW5dZnBVap8C5egQ9Z6pHyjsh5MNy83iPqqRuq")
      )
    ).to.be.true;
  });

  it("createProgramAddress", async () => {
    const programId = new Address("BPFLoader1111111111111111111111111111111111");
    const publicKey = new Address("SeedPubey1111111111111111111111111111111111");

    let programAddress = Address.createProgramAddress(
      [Buffer.from("", "utf8"), Buffer.from([1])],
      programId
    );
    expect(
      programAddress.equals(
        new Address("3gF2KMe9KiC6FNVBmfg9i267aMPvK37FewCip4eGBFcT")
      )
    ).to.be.true;

    programAddress = Address.createProgramAddress(
      [Buffer.from("☉", "utf8")],
      programId
    );
    expect(
      programAddress.equals(
        new Address("7ytmC1nT1xY4RfxCV2ZgyA7UakC93do5ZdyhdF3EtPj7")
      )
    ).to.be.true;

    programAddress = Address.createProgramAddress(
      [Buffer.from("Talking", "utf8"), Buffer.from("Squirrels", "utf8")],
      programId
    );
    expect(
      programAddress.equals(
        new Address("HwRVBufQ4haG5XSgpspwKtNd3PC9GM9m1196uJW36vds")
      )
    ).to.be.true;

    programAddress = Address.createProgramAddress(
      [publicKey.toBytes()],
      programId
    );
    expect(
      programAddress.equals(
        new Address("GUs5qLUfsEHkcMB9T38vjr18ypEhRuNWiePW2LoK4E3K")
      )
    ).to.be.true;

    const programAddress2 = Address.createProgramAddress(
      [Buffer.from("Talking", "utf8")],
      programId
    );
    expect(programAddress.equals(programAddress2)).to.eq(false);

    expect(() => {
      Address.createProgramAddress([Buffer.alloc(MAX_SEED_LEN + 1)], programId);
    }).to.throw();
  });

  it("findProgramAddress", async () => {
    const programId = new Address("BPFLoader1111111111111111111111111111111111");
    let [programAddress, nonce] = Address.findProgramAddress(
      [Buffer.from("", "utf8")],
      programId
    );
    expect(
      programAddress.equals(
        Address.createProgramAddress(
          [Buffer.from("", "utf8"), Buffer.from([nonce])],
          programId
        )
      )
    ).to.be.true;
  });

    it("input length validation", () => {
    expect(() => {
      new Address(new Uint8Array(ADDRESS_BYTES + 1));
    }).to.throw(/Invalid Uint8Array length/);

    expect(() => {
        new Address(new Uint8Array(ADDRESS_BYTES - 1));
    }).to.throw(/Invalid Uint8Array length/);

    expect(() => {
      new Address(new Array(ADDRESS_BYTES + 1).fill(0));
    }).to.throw(/Invalid Array length/);

    expect(() => {
        new Address(new Array(ADDRESS_BYTES - 1).fill(0));
    }).to.throw(/Invalid Array length/);

    const programId = new Address("11111111111111111111111111111111");

    const tooManySeeds = new Array(MAX_SEEDS + 1).fill(new Uint8Array(1));
    expect(() => {
      Address.createProgramAddress(tooManySeeds, programId);
    }).to.throw(/Too many seeds/);

    expect(() => {
      Address.findProgramAddress(tooManySeeds, programId);
    }).to.throw(/Too many seeds/);

    expect(() => {
      Address.createProgramAddress([Buffer.alloc(MAX_SEED_LEN + 1)], programId);
    }).to.throw(/Seed 0 too long/);

    expect(() => {
      Address.findProgramAddress([Buffer.alloc(MAX_SEED_LEN + 1)], programId);
    }).to.throw(/Seed 0 too long/);
  });
});
