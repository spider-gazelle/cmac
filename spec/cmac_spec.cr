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
