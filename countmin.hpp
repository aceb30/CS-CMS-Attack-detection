/*
 * countmin.cpp
 * Implementación del sketch CountMin
 * Está inspirada en gran medida por la implementación mostrada en clases
 * Se han modificado algunos aspectos:
 * -Se delegó la creación de los d hashes independientes (semillas) al archivo carter_wegman_hash
 * -Se cambió la familia de hashes de MurmurHash a la familia Carter Wegman (ver informe)
 * -Se añadieron métodos de suma, resta y limpieza de sketch para usar en anillo de estimadores
 * De esta forma este archivo se dedica exclusivamente a CountMin y queda adaptado para el anillo
*/

#pragma once
#include <vector>
#include <algorithm>
#include <limits>
#include <stdexcept>
#include "carter_wegman_hash.hpp"

class CountMin {
private:
    int d_;
    int w_;
    std::vector<std::vector<long long>> C_;
    
    CarterWegmanHash hasher_;

public:
    // Inicializar d, w, la matriz y entregar parámetros al hash
    CountMin(int d, int w, uint64_t seed = 12345) : 
        d_(d), w_(w), 
        C_(d, std::vector<long long>(w, 0)),
        hasher_(d, w, seed) {
        
        if (d_ <= 0 || w_ <= 0) {
            throw std::invalid_argument("d y w deben ser positivos");
        }
    }

    void insertar(Key x, long long c = 1) {
        for (int j = 0; j < d_; j++) {
            C_[j][hasher_.hash(x, j)] += c;
        }
    }

    long long estimar(Key x) const {
        long long freq_est = std::numeric_limits<long long>::max();
        for (int j = 0; j < d_; j++) {
            freq_est = std::min(freq_est, C_[j][hasher_.hash(x, j)]);
        }
        return freq_est;
    }

    // Suma los contadores de otro sketch a este (A = A + S_nuevo)
    void sumar(const CountMin& otro) {
        for (int j = 0; j < d_; j++) {
            for (int k = 0; k < w_; k++) {
                C_[j][k] += otro.C_[j][k];
            }
        }
    }

    // Resta los contadores de otro sketch de este (A = A - S_viejo)
    void restar(const CountMin& otro) {
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