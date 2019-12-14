require "spec"
require "../src/cmac"

TEST_KEY = Bytes[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]

def test_vectors
  test_lines = File.read_lines("./spec/test_vectors.txt").map(&.strip).reject(&.empty?)
  test_lines.each_slice(5).map do |lines|
    name = lines.shift
    data = {} of String => Bytes
    [lines[0], lines[1], lines[3]].each do |line|
      key, value = line.split('=').map(&.strip)
      data[key.downcase] = value.size > 2 ? value[2..-1].hexbytes : Bytes.new(0)
    end
    truncate = lines[2].split('=').map(&.strip)[1].to_i

    {
      name:     name,
      key:      data["key"],
      message:  data["message"],
      tag:      data["tag"],
      truncate: truncate,
    }
  end.to_a
end
