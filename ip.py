from iputils import *


def ignore_bits(data, nbits):
    return data >> nbits << nbits


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
        self.counter = -1

    def __raw_recv(self, datagrama):
        (
            dscp,
            ecn,
            identification,
            flags,
            frag_offset,
            ttl,
            proto,
            src_addr,
            dst_addr,
            payload,
        ) = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        for cidr, next_hop in self.tabela:
            net, fixed_bits = cidr.split("/")

            variable_bits = 32 - int(fixed_bits)

            (net,) = struct.unpack("!I", str2addr(net))
            (dest,) = struct.unpack("!I", str2addr(dest_addr))

            if ignore_bits(net, variable_bits) == ignore_bits(dest, variable_bits):
                return next_hop

    def _counter_next(self):
        self.counter += 1
        return self.counter

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
        self.tabela = tabela
        pass

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

        # Estrutura do header
        header = struct.pack(
            "!BBHHHBBHII",
            (4 << 4) | 5,         # Version, IHL
            0,                    # DSCP, ECN
            20 + len(segmento),   # Total Length
            self._counter_next(), # Identification
            0,                    # Flags, Fragment Offset
            64,                   # Time To Live
            6,                    # Protocol (TCP)
            0,                    # Checksum
            0,                    # Source  IP Address
            0                     # Destination IP Address
        )

        header = bytearray(header)

        # Adicionando endereços de origem e destino
        header[12:16] = str2addr(self.meu_endereco)
        header[16:20] = str2addr(dest_addr)

        # Calculando e adicionando o checksum
        header[10:12] = struct.pack("!H", calc_checksum(header))

        header = bytes(header)

        datagrama = header + segmento

        self.enlace.enviar(datagrama, next_hop)
