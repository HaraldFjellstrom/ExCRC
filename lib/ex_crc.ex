defmodule ExCRC do
  @moduledoc """
    Calculate CRC checksums
  """
  import Bitwise

    # poly=0x8005, start=0xffff, check=0x4b37
  @doc """
    Compute and return the CRC16/MODBUS-TRUE checksum of a binary _value_.
  """
  @spec crc16modbus(value :: binary, crc :: non_neg_integer) :: non_neg_integer
  def crc16modbus(value, crc \\ 0xFFFF) do
    import ExCRC.Tables, only: [modbus_table: 0]
    calc_modbus(:binary.bin_to_list(value), crc, modbus_table())
  end

  # poly=0x1021, start=0xffff, check=0x29b1
  @doc """
    Compute and return the CRC16/CCITT-FALSE checksum of a binary _value_.
  """
  @spec crc16ccitt(value :: binary, crc :: non_neg_integer) :: non_neg_integer
  def crc16ccitt(value, crc \\ 0xFFFF) do
    import ExCRC.Tables, only: [ccitt_table: 0]
    calc_ccitt(:binary.bin_to_list(value), crc, ccitt_table())
  end

  # poly=0x1021, start=0x0000, check=0x2189, refin=yes, refout=yes
  @doc """
    Compute and return the CRC16/CCITT-TRUE checksum of a binary _value_
  """
  @spec crc16kermit(value :: binary, crc :: non_neg_integer()) :: non_neg_integer
  def crc16kermit(value, crc \\ 0x0000) do
    import ExCRC.Tables, only: [kermit_table: 0]
    crc = calc_kermit([], crc, %{})
    calc_kermit(:binary.bin_to_list(value), crc, kermit_table())
  end

  # poly=0x1021, start=0x0000, check=0x31c3
  @doc """
    Compute and return the CRC16/XMODEM checksum of a binary _value_.
  """
  @spec crc16xmodem(value :: binary, crc :: non_neg_integer) :: non_neg_integer
  def crc16xmodem(value, crc \\ 0x0000) do
    import ExCRC.Tables, only: [ccitt_table: 0]
    calc_ccitt(:binary.bin_to_list(value), crc, ccitt_table())
  end

  # Calculate CRC using ccitt table
  @spec calc_ccitt([byte], non_neg_integer, table :: map) :: non_neg_integer
  defp calc_ccitt([x | rem], crc, table) do
    key = bxor(crc >>> 8, x) &&& 0xFF
    crc = bxor(crc <<< 8, table[key])
    calc_ccitt(rem, crc &&& 0xFFFF, table)
  end

  defp calc_ccitt([], crc, _), do: crc

  # Calculate CRC using kermit table
  @spec calc_kermit([byte], non_neg_integer, table :: map) :: non_neg_integer
  defp calc_kermit([x | rem], crc, table) do
    key = bxor(crc, x) &&& 0xFF
    crc = bxor(crc >>> 8, table[key])
    calc_kermit(rem, crc &&& 0xFFFF, table)
  end

  defp calc_kermit([], crc, _) do
    low_byte = (crc &&& 0xFF00) >>> 8
    high_byte = (crc &&& 0x00FF) <<< 8
    low_byte ||| high_byte
  end

  # Calculate CRC using modbus table
  @spec calc_modbus([byte], non_neg_integer, table :: map) :: non_neg_integer
  defp calc_modbus([x | rem], crc, table) do
    key = bxor(crc, x) &&& 0xFF
    crc = bxor(crc >>> 8, table[key])
    calc_modbus(rem, crc &&& 0xFFFF, table)
  end

  defp calc_modbus([], crc, _), do: crc
end
