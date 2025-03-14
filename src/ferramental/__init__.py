import base64
import binascii
import textwrap
from datetime import datetime
from typing import Optional, Union


class Ferramental:
    @staticmethod
    def armored(base_bytes: bytes = None,
                start_banner: str = '--- BEGIN ---',
                end_banner: str = '--- END ---',
                width: int = 72) -> Optional[str]:
        """
        Codifica um conjunto de bytes em base64 e a formata com banners de
         início e fim.

        Args:
            base_bytes (str): O conjunto de bytes a ser formatado.
            start_banner (str): O banner de início a ser adicionado. Padrão
                                é '--- BEGIN ---'.
            end_banner (str): O banner de fim a ser adicionado. Padrão é
                              '--- END ---'.
            width (int): A largura máxima de cada linha da string codificada.
                         Padrão é 72.

        Returns:
            str: A string codificada em base64 e formatada com os banners de início e fim.
        """
        if base_bytes is None:
            return None
        if not isinstance(base_bytes, bytes):
            raise ValueError('base_bytes must be a byte type')
        try:
            base_bytes = base64.b64encode(base_bytes).decode('utf-8')
        except (ValueError, TypeError):
            raise ValueError('base64 encoding error')
        wrapped = textwrap.fill(base_bytes, width)
        return f"{start_banner}\n{wrapped}\n{end_banner}"

    @staticmethod
    def unarmor(base_str: str,
                start_banner: str = '--- BEGIN ---',
                end_banner: str = '--- END ---') -> Optional[bytes]:
        """
        Remove banners de início e fim de uma string em base64 e retorna o
         conjunto de bytes.

        Args:
            base_str (str): A string base codificada em base64 com banners.
            start_banner (str): O banner de início a ser removido. Padrão é
                                '--- BEGIN ---'.
            end_banner (str): O banner de fim a ser removido. Padrão é
                              '--- END ---'.

        Returns:
            Optional[bytes]: O conjunto de bytes decodificado ou None se os
                             banners não forem encontrados.
        """
        if base_str is None:
            return None
        if not isinstance(base_str, str):
            raise ValueError('base_str must be a str type')
        lines = base_str.splitlines()
        try:
            start_idx = lines.index(start_banner)
            end_idx = lines.index(end_banner)
        except ValueError('Missing start and/or end banner'):
            return None
        base_str = ''.join(lines[start_idx + 1:end_idx]).strip()
        try:
            return base64.b64decode(base_str)
        except (binascii.Error, ValueError):
            raise ValueError('base64 decoding error')

    @staticmethod
    def safe_fromisoformat(value) -> Optional[datetime]:
        """
        Converte uma string no formato ISO 8601 para um objeto datetime.

        Args:
            value (Union[str, datetime]): A string no formato ISO 8601 ou um objeto datetime.

        Returns:
            Optional[datetime]: O objeto datetime correspondente ou None se a conversão falhar.
        """
        try:
            return datetime.fromisoformat(value) if isinstance(value, str) else value
        except ValueError:
            return None

    @staticmethod
    def crc8(data: Union[str, bytes] = None) -> bytes:
        """
        Calcula o CRC-8 de uma string ou bytes.

        Args:
            data (Union[str, bytes]): A string ou bytes para calcular o CRC-8.

        Returns:
            bytes: O valor CRC-8 calculado como um único byte.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        if not isinstance(data, bytes):
            raise ValueError('data must be a byte or str type')
        crc = 0
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x80:
                    crc = (crc << 1) ^ 0x07
                else:
                    crc <<= 1
                crc &= 0xFF
        return bytes([crc])
