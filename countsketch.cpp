/*
 * countsketch.cpp
 * Implementación del sketch CountSketch
*/

#pragma once
#include <vector>
#include <algorithm>
#include <limits>
#include <stdexcept>
#include "carter_wegman_hash.hpp"
#include "sign_hash.hpp"

class CountSketch {
  private:
    int d_;
    int w_;
    std::vector<std::vector<long long>> C_;

    CarterWegmanHash hasher_;
    SignHash signHasher_;

  public:
    //Inicializar d, w, la matriz y los hashes
    CountSketch(int d, int w, uint64_t seed = 12345) : 
    d_(d), w_(w),
    C_(d, std::vector<long long>(w,0)),
    hasher_(d, w, seed),
    //El offset de 100 de la seed asegura independencia entre hashes signed y regular
    signHasher_(d, seed + 100) {
      if (d_ <= 0 || w_ <= 0) {
            throw std::invalid_argument("d y w deben ser positivos");
        }
    }

    void insertar(Key x, long long c = 1) {
        for (int j = 0; j < d_; j++) {
            C_[j][hasher_.hash(x, j)] += signHasher_.hash(x,j) * c;
        }
    }

    //Retorna la mediana 
    long long estimar(Key x) const {
        std::vector<long long> hashed(d_);
        for (int j = 0; j < d_; j++) {
            // La única modificación respecto de CountMedian es multiplicar por el hash de signo
            hashed[j] = signHasher_.hash(x,j) * C_[j][hasher_.hash(x, j)];
        }

        if (hashed.empty()) return long long(0);
        
        std::sort(hashed.begin(), hashed.end());

        size_t size = hashed.size();
        if (size % 2 != 0){
          return hashed[size/2];
        } else {
          // División entera, descartando los decimales (truncamiento hacia cero)
          return (hashed[size / 2 - 1] + hashed[size / 2]) / 2;
        }

    }
    
    // Suma los contadores de otro sketch a este (A = A + S_nuevo)
    void sumar(const CountSketch& otro) {
        for (int j = 0; j < d_; j++) {
            for (int k = 0; k < w_; k++) {
                C_[j][k] += otro.C_[j][k];
            }
        }
    }

    // Resta los contadores de otro sketch de este (A = A - S_viejo)
    void restar(const CountSketch& otro) {
        for (int j = 0; j < d_; j++) {
            for (int k = 0; k < w_; k++) {
                C_[j][k] -= otro.C_[j][k];
            }
        }
    }

    // Limpia la matriz a ceros para reutilizar el sketch en el anillo
    void limpiar() {
        for (int j = 0; j < d_; j++) {
            // std::fill es altamente optimizado por el compilador
            std::fill(C_[j].begin(), C_[j].end(), 0);
        }
    }
    
    //Como d_ y w_ son privadas, hacemos un método para verlas
    int filas() const { return d_; }
    int columnas() const { return w_; }


};