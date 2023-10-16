require "./spec_helper"

describe CMAC do
  describe "sign" do
    test_vectors.each do |options|
      it "matches the \"#{options[:name]}\" test vector" do
        cmac = CMAC.new(options[:key])
        input = options[:message].clone
        output = cmac.sign(options[:message], options[:truncate])
        output.should eq(options[:tag])

        # Ensure memory not modified
        input.should eq(options[:message])
      end
    end

    it "gives a truncated output if requested" do
      cmac = CMAC.new(TEST_KEY)
      output = cmac.sign("attack at dawn", 12)
      output.size.should eq(12)
    end

    it "passes test vectors" do
      nist_key128 = "2b7e151628aed2a6abf7158809cf4f3c".hexbytes
      cmac = CMAC.new(nist_key128)
      cmac.sign("").should eq("bb1d6929e95937287fa37d129b756746".hexbytes)

      output = cmac.sign("6bc1bee22e409f96e93d7e117393172a".hexbytes)
      output.should eq("070a16b46b4d4144f79bdd9dd04a287c".hexbytes)

      cmac = CMAC.new("000102030405060708090a0b0c0d0e0fedcb".hexbytes)
      output = cmac.sign("000102030405060708090a0b0c0d0e0f10111213".hexbytes)
      output.should eq("84a348a4a45d235babfffc0d2b4da09a".hexbytes)

      cmac = CMAC.new("000102030405060708090a0b0c0d0e0f".hexbytes)
      output = cmac.sign("000102030405060708090a0b0c0d0e0f10111213".hexbytes)
      output.should eq("980ae87b5f4c9c5214f5b6a8455e4c2d".hexbytes)

      cmac = CMAC.new("00010203040506070809".hexbytes)
      output = cmac.sign("000102030405060708090a0b0c0d0e0f10111213".hexbytes)
      output.should eq("290d9e112edb09ee141fcf64c0b72f3d".hexbytes)
    end

    it "raises error if truncation request is greater than 16 bytes" do
      cmac = CMAC.new(TEST_KEY)
      expect_raises(CMAC::Error, "Tag cannot be greater than maximum (16 bytes)") do
        cmac.sign("attack at dawn", 17)
      end
    end

    it "raises error if truncation request is less than 8 bytes" do
      cmac = CMAC.new(TEST_KEY)
      expect_raises(CMAC::Error, "Tag cannot be less than minimum (8 bytes)") do
        cmac.sign("attack at dawn", 7)
      end
    end
  end

  describe "valid_message?" do
    it "is true for matching messages" do
      message = "attack at dawn"
      cmac = CMAC.new(TEST_KEY)
      tag = cmac.sign(message)
      result = cmac.valid_message?(tag, message)
      result.should be_truthy
    end

    it "is false for modified messages" do
      cmac = CMAC.new(TEST_KEY)
      tag = cmac.sign("attack at dawn")
      result = cmac.valid_message?(tag, "attack at dusk")
      result.should be_falsey
    end
  end
end
