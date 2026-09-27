/*
 * sign_hash.cpp
 * Este módulo se encarga de crear y administrar una familia de d hashes del tipo
 * H(x) = s{LSB[(ax + b) mod p]}
 * Con LSB[] definida como la operación Least Significant Bit
 * s() definida como:
 * s() = {1, cuando el input es 0 ; -1 cuando el input es 1
 * La familia {Ha,b} para a en {1,...,p-1}, b en {0,...,p-1}
 * p, un número primo grande (Mersenne Prime)
 * es aproximadamente 2-independiente (ver informe)
 * La elección del Mersenne Prime está justificada en el informe 
 * Para hashear un elemento, basta con llamar al método hash, indicando el elemento y la fila en el hash
*/

#pragma once
#include <vector>
#include <cstdint>
#include <random>

typedef unsigned __int128 Key;

class SignHash {
  private:
    int d_;
    std::vector<uint64_t> a_;
    std::vector<uint64_t> b_;

    // ULL = Unsigned Long Long, para poder hacer el shift grande de 61 bits
    static constexpr uint64_t MERSENNE_PRIME = (1ULL << 61) - 1;

    /*
     * El uso del Mersenne Prime ayuda a calcular el módulo de forma rápida
     * usando operaciones de bits.
     */
    inline uint64_t fast_mersenne_mod(unsigned __int128 v) const {
        uint64_t v_low = (uint64_t)v & MERSENNE_PRIME;
        uint64_t v_high = (uint64_t)(v >> 61);
        uint64_t sum = v_low + v_high;
        if (sum >= MERSENNE_PRIME) {
            sum -= MERSENNE_PRIME;
        }
        return sum;
    }

  public:
    SignHash(int d, uint64_t seed = 12345): d_(d) {
      a_.resize(d_);
      b_.resize(d_);
      /*
         * mt19937_64 rng(sed) es la implementación estándar en C++ de un Pseudorandom Number Generator (rng)
         * mt = Mersenne Twister, un algoritmo rng que se basta en números primos de Mersenne
         * Esto es, los mismos números que usamos para la operación rápida de módulo
         * Pasarle la seed al constructor permite reproducir los resultados del experimento fácilmente
         */
        std::mt19937_64 rng(seed);
        std::uniform_int_distribution<uint64_t> dist_a(1, MERSENNE_PRIME - 1);
        std::uniform_int_distribution<uint64_t> dist_b(0, MERSENNE_PRIME - 1);

        for (int i = 0; i < d_; i++) {
            //dist_a(rng) mapea los bits "aleatorios" que el rng generó a una distribución uniforme
            a_[i] = dist_a(rng);
            b_[i] = dist_b(rng);
        }
    }

   int hash(Key x, int row) const {
        // Hash universal, 2-independiente: H(x) = s{LSB[(ax + b) mod p]}
        unsigned __int128 ax_b = (unsigned __int128)a_[row] * x + b_[row];
        uint64_t h = fast_mersenne_mod(ax_b);
        uint32_t LSB = h & 1; // LSB(h)
        if(LSB == 0){
          return 1;
        }
        return -1;
    }
};