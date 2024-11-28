defmodule ExCRCTest do
  @moduledoc false
  use ExUnit.Case

  # @tag :skip
  test "crc16ccitt/1 computes the CRC of an empty string as 0xFFFF" do
    assert ExCRC.crc16ccitt("") == 0xffff
  end

  # @tag :skip
  test "crc16ccitt/1 computes the CRC of a space as 0xC592" do
    assert ExCRC.crc16ccitt(" ") == 0xc592
  end

  # @tag :skip
  test "crc16ccitt/1 computes the CRC of '123456789' as 0x29B1" do
    assert ExCRC.crc16ccitt("123456789") == 0x29b1
  end

  # @tag :skip
  test "crc16ccitt/2 computes the CRC of '12345' and '6789' as 0x29B1" do
    crc =  ExCRC.crc16ccitt("12345")
    assert ExCRC.crc16ccitt("6789", crc) == 0x29b1
  end

  # @tag :skip
  test "crc16ccitt/1 computes the CRC of 'Lammert Bies' as 0x4A31" do
    assert ExCRC.crc16ccitt("Lammert Bies") == 0x4a31
  end

  # @tag :skip
  test "crc16kermit/1 computes the CRC of an empty string as 0x0000" do
    assert ExCRC.crc16kermit("") == 0
  end

  # @tag :skip
  test "crc16kermit/1 computes the CRC of a space as 0x0221" do
    assert ExCRC.crc16kermit(" ") == 0x0221
  end

  # @tag :skip
  test "crc16kermit/1 computes the CRC of '123456789' as 0x8921" do
    assert ExCRC.crc16kermit("123456789") == 0x8921
  end

  # @tag :skip
  test "crc16kermit/2 computes the CRC of '12345' and '6789' as 0x8921" do
    crc = ExCRC.crc16kermit("12345")
    assert ExCRC.crc16kermit("6789", crc) == 0x8921
  end

  # @tag :skip
  test "crc16kermit/1 computes the CRC of 'Lammert Bies' as 0xF80D" do
    assert ExCRC.crc16kermit("Lammert Bies") == 0xf80d
  end

  # @tag :skip
  test "crc16xmodem/1 computes the CRC of an empty string as 0x0000" do
    assert ExCRC.crc16xmodem("") == 0
  end

  # @tag :skip
  test "crc16xmodem/1 computes the CRC of a space as 0x2462" do
    assert ExCRC.crc16xmodem(" ") == 0x2462
  end

  # @tag :skip
  test "crc16xmodem/1 computes the CRC of '123456789' as 0x31C3" do
    assert ExCRC.crc16xmodem("123456789") == 0x31c3
  end

  # @tag :skip
  test "crc16xmodem/2 computes the CRC of '12345' and '6789' as 0x31C3" do
    crc = ExCRC.crc16xmodem("12345")
    assert ExCRC.crc16xmodem("6789", crc) == 0x31c3
  end

  # @tag :skip
  test "crc16xmodem/1 computes the CRC of 'Lammert Bies' as 0xCEC8" do
    assert ExCRC.crc16xmodem("Lammert Bies") == 0xcec8
  end

    # @tag :skip
    test "crc16modbus/1 computes the CRC of an empty string as 0xFFFF" do
      assert ExCRC.crc16modbus("") == 0xFFFF
    end

    # @tag :skip
    test "crc16modbus/1 computes the CRC of a space as 0x98BE" do
      assert ExCRC.crc16modbus(" ") == 0x98BE
    end

    # @tag :skip
    test "crc16modbus/1 computes the CRC of '123456789' as 0x4B37" do
      assert ExCRC.crc16modbus("123456789") == 0x4B37
    end

    # @tag :skip
    test "crc16modbus/1 computes the CRC of 'Lammert Bies' as 0xCEC8" do
      assert ExCRC.crc16modbus("Lammert Bies") == 0xB45C
    end

end
