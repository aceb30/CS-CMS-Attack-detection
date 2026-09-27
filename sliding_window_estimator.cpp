/*
 * sliding_window_estimator.cpp
 * Este módulo se encarga de orquestrar el anillo de sketches y contadores
 * Lee el archivo de la traza
 * Y evalúa los heavy hitters
*/

#include <iostream>
#include <vector>
#include <cmath>
#include <string>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "countmin.hpp"
#include "countmedian.hpp"
#include "countsketch.hpp"

/*
 * Usamos la misma estructura definida en los demás archivos
 * En donde:
 * - ts_us: timestamp en microsegundos desde unix epoch
 * - sport, dport: source, destination ports, identificadores de aplicación
 * - len: longitud (tamaño) del paquete
 * - proto: protocolo
 * - flags: bitmask, donde
 *   - Bit 0-3: Estados de concección TCP (SYN, ACK, FIN, RST)
 *   - Bit 4 (F-SYNTHETIC): Flag de ataque, 1 para ataques, 0 para tráfico normal
 *   - Bit 5: Marca si el paquete original era Ipv6
 *
 * pragma pack se asegura de que no haya relleno (padding) entre campos
*/
#pragma pack(push, 1)
struct Record {
    uint64_t ts_us;
    uint32_t src, dst;
    uint16_t sport, dport, len;
    uint8_t proto, flags;
};
#pragma pack(pop)
static_assert(sizeof(Record) == 24, "el registro debe ocupar 24 bytes");

// Helper para convertir IP de string a uint32_t
bool parse_ipv4(const char* s, uint32_t* out) {
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

// Helper para convertir uint32_t IP a string
std::string ip_to_string(uint32_t ip) {
    char buf[16];
    sprintf(buf, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    return std::string(buf);
}


inline uint64_t calcular_q(uint64_t ts, uint64_t t0, uint64_t p_us) {
    uint64_t delta = ts - t0;
    return (delta - 1) / p_us + 1;
}

/*
 * Usamos un c++ template para la ventana deslizante
 * Los templates permiten crear código genérico que funciona para cualquier tipo de dato
 * Usando esta blueprint, podemos luego manejar cualquier tipo de sketch
*/
template <typename SketchType>
void run_sliding_window(const Record* trace, size_t n_packets, int d, int w, double phi, uint32_t target_ip, const std::string& key_type){
  /*
  * Configuración temporal.
  * W_us corresponde a W = 60 segundos, en microsegundos, tamaño de la ventana
  * p_us corresponde a p = 10 segundos, tamaño de la sub-ventana
  */
  const uint64_t W_us = 60ULL * 1000000ULL;
  const uint64_t p_us = 10ULL * 1000000ULL;
  const int m = 6; // W / p

  if (n_packets == 0) return;

  uint64_t t0 = trace[0].ts_us;
  uint64_t tau = t0 + W_us; // Primera evaluación

  // Inicializar el anillo de m sketches S y el agregado A
  std::vector<SketchType> S(m, SketchType(d, w, 12345));
  SketchType A(d, w, 12345);

  // Inicializar el anillo escalar de contadores
  std::vector<uint64_t> N_sub(m, 0);
  uint64_t N_total = 0;

  size_t win_id = 0; // Puntero al paquete actual

  //CSV Header
  printf("win,tau_us,N,threshold,key,f_est,is_hh\n");

  // Ciclo principal
  for (size_t i = 0; i < n_packets; ++i) {
      uint64_t ts = trace[i].ts_us;

      //El intervalo es (t0, t0 + W], abierto a la izquierda.
      // El paquete en t0 queda estrictamente fuera de la ventana.
      if (ts <= t0) continue;

      // Si cruzamos el límite, evaluamos y deslizamos
      while (ts > tau) {
          uint64_t threshold = (uint64_t)std::ceil(phi * N_total);
          /*
          * Como caso límite, una ventana podría estar vacía, en cuyo caso Tj=0
          * El problema es que si el treshold es 0, cualquier cosa sale como HH
          * Así que forzamos al treshold a ser 1 por lo menos
          */
          if (threshold == 0) threshold = 1;
          
          //Estimación de frecuencia y determinación HH
          long long f_est = A.estimar(target_ip);
          int is_hh = (f_est >= threshold) ? 1 : 0;
          
          printf("%zu,%llu,%llu,%llu,%s,%lld,%d\n", 
            win_id, (unsigned long long)tau, (unsigned long long)N_total, (unsigned long long)threshold, ip_to_string(target_ip).c_str(), f_est, is_hh);

          /*
          * Deslizamiento
          */
          uint64_t q_tau = (tau - t0) / p_us;
          uint64_t q_expira = q_tau - m + 1;
          int slot_expira = (q_expira - 1) % m;

          A.restar(S[slot_expira]);
          N_total -= N_sub[slot_expira];

          S[slot_expira].limpiar();
          N_sub[slot_expira] = 0;

          tau += p_us;
          win_id++;
      }

      /*
       * Cálculo de la subventana actual
       * Resta -1 para ajuste de cerradura a la derecha (] de la subventana
       */
      uint64_t q = calcular_q(ts, t0, p_us);
      int slot = (q - 1) % m;

      //Acá procesamos la key (IP), source o destination, dependiendo del caso
      uint32_t key = (key_type == "src") ? trace[i].src : trace[i].dst;

      S[slot].insertar(key);
      A.insertar(key);
      
      N_sub[slot]++;
      N_total++;
  }
}

int main(int argc, char** argv) {
    if (argc < 7) {
        fprintf(stderr, "Uso: %s TRAZA.bin ESTIMADOR(cm|cs) D W KEY_TYPE(src|dst) TARGET_IP\n", argv[0]);
        return 1;
    }

    const char* path = argv[1];
    std::string estimator = argv[2];
    int d = atoi(argv[3]);
    int w = atoi(argv[4]);
    std::string key_type = argv[5];
    uint32_t target_ip = 0;
    
    if (!parse_ipv4(argv[6], &target_ip)) {
        fprintf(stderr, "IP invalida.\n");
        return 1;
    }

    // MAPEAR EL ARCHIVO (Código estándar tomado de exact_hh.cpp)
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); exit(1); }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); exit(1); }
    
    //Lectura eficiente del archivo
    void* p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    close(fd);
    madvise(p, st.st_size, MADV_SEQUENTIAL);
    
    const Record* trace = (const Record*)p;
    size_t n_packets = st.st_size / sizeof(Record);

    double phi = 0.01;

    // Inyectar el sketch en la plantilla 
    if (estimator == "cm") {
        run_sliding_window<CountMin>(trace, n_packets, d, w, phi, target_ip, key_type);
    } else if (estimator == "cs") {
        run_sliding_window<CountSketch>(trace, n_packets, d, w, phi, target_ip, key_type);
    } else {
        fprintf(stderr, "Estimador desconocido. Use 'cm' o 'cs'.\n");
    }

    //Fin de la lectura: Des-mapeo del archivo, se rompe el enlace de lectura
    munmap(p, st.st_size);
    return 0;
}