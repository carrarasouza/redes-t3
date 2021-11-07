from ctypes import sizeof
import struct
from grader.tcputils import addr2str, calc_checksum, str2addr
from iputils import *


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.ident = 0

    def icmp(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        header = struct.pack('!BBHI', 11, 0, 0, 0)
        icmp_Ip_Header = datagrama[:28]
        check_sum = calc_checksum(header + icmp_Ip_Header)
        header = struct.pack('!BBHI', 11, 0, check_sum, 0)
        return header + icmp_Ip_Header

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            ttl -= 1
            if ttl == 0:
                proto = 1
                next_hop = self._next_hop(src_addr)
                payload = self.icmp(datagrama)
                aux = dst_addr
                dst_addr = src_addr
                src_addr = self.meu_endereco
                ttl = 64

            datagrama = struct.pack('!BBHHHBBHII', 0x45, 0, (20 + len(payload)), self.ident, 0, ttl, proto, 0, 
                                    int.from_bytes(str2addr(src_addr), byteorder="big"),
                                    int.from_bytes(str2addr(dst_addr), byteorder="big"))

            check_sum = calc_checksum(datagrama)
            datagrama = struct.pack('!BBHHHBBHII', 0x45, 0, (20 + len(payload)), self.ident, 0, ttl, proto, 
                                    check_sum, 
                                    int.from_bytes(str2addr(src_addr), byteorder="big"),
                                    int.from_bytes(str2addr(dst_addr), byteorder="big"))
            self.enlace.enviar(datagrama + payload, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        addrIPv4, = struct.unpack('!I', str2addr(dest_addr))
        result_next_hop = None
        max_mask = 33

        for tupla in self.tabela:
            cidr, next_hop = tupla;
            cidr, mask  = cidr.split("/")
            net, = struct.unpack('!I', str2addr(cidr))
            mask = 32 - int(mask)
            if (addrIPv4 >> mask << mask) == (net >> mask << mask):
                if mask < max_mask:
                    max_mask = mask
                    result_next_hop = next_hop
        return result_next_hop


    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        datagrama = struct.pack('!BBHHHBBHII', 0x45, 0, (20 + len(segmento)), self.ident, 0, 64, 6, 0, 
                                int.from_bytes(str2addr(self.meu_endereco), byteorder="big"), 
                                int.from_bytes(str2addr(dest_addr), byteorder="big"))

        check_sum = calc_checksum(datagrama)
        datagrama = struct.pack('!BBHHHBBHII', 0x45, 0, (20 + len(segmento)), self.ident, 0, 64, 6, check_sum, 
                               int.from_bytes(str2addr(self.meu_endereco), byteorder="big"),
                               int.from_bytes(str2addr(dest_addr), byteorder="big"))
        self.ident += 1
        self.enlace.enviar(datagrama + segmento, next_hop)
