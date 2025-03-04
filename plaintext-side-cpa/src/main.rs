/*
 *  File: main.rs
 *  Author: Prasanna Paithankar (21CS30065)
 *  Date: 05/04/2025
 *
 *  Course: Hardware Security (CS60004) Spring 2025
 *  Assignment 1: Plaintext Side CPA
 *
 *  Refer to the README.md for other details.
 */

use csv::ReaderBuilder;
use ndarray::{Array1, Array2, Zip};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

fn compute_correlation(x: &Array1<f64>, y: &Array1<f64>) -> f64 {
    let x_mean = x.mean().unwrap();
    let y_mean = y.mean().unwrap();

    let numerator = Zip::from(x)
        .and(y)
        .map_collect(|&xi, &yi| (xi - x_mean) * (yi - y_mean))
        .sum();

    let denominator = (Zip::from(x)
        .map_collect(|&xi| (xi - x_mean).powi(2))
        .sum()
        .sqrt())
        * (Zip::from(y)
            .map_collect(|&yi| (yi - y_mean).powi(2))
            .sum()
            .sqrt());

    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

const SBOX_INV: [u8; 256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
];

fn hamming_weight(byte: u8) -> u8 {
    byte.count_ones() as u8
}

fn read_trace_file(filename: &str) -> (Vec<[u8; 16]>, Vec<[u8; 16]>, Array2<f64>) {
    let mut rdr = ReaderBuilder::new()
        .has_headers(true)
        .from_path(filename)
        .unwrap();
    let mut plaintexts = Vec::new();
    let mut ciphertexts = Vec::new();
    let mut traces = Vec::new();

    for result in rdr.records() {
        let record = result.unwrap();
        let plaintext: [u8; 16] = record
            .iter()
            .take(16)
            .map(|x| u8::from_str_radix(x, 16).unwrap())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        let ciphertext: [u8; 16] = record
            .iter()
            .skip(16)
            .take(16)
            .map(|x| u8::from_str_radix(x, 16).unwrap())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        let trace: Vec<f64> = record
            .iter()
            .skip(32)
            .map(|x| x.parse::<f64>().unwrap())
            .collect();

        plaintexts.push(plaintext);
        ciphertexts.push(ciphertext);
        traces.push(trace);
    }

    let trace_matrix = Array2::from_shape_vec(
        (traces.len(), traces[0].len()),
        traces.into_iter().flatten().collect(),
    )
    .unwrap();
    (plaintexts, ciphertexts, trace_matrix)
}

fn compute_cpa(plaintexts: &[[u8; 16]], traces: &Array2<f64>) -> u8 {
    let num_samples = traces.shape()[1];
    let mut best_key = 0;
    let mut best_corr: f64 = 0.0;

    for key_guess in 0..=255 {
        let model: Array1<f64> = plaintexts
            .iter()
            .map(|pt| hamming_weight(SBOX_INV[(pt[0] ^ key_guess) as usize]) as f64)
            .collect();

        let correlations: Vec<f64> = (0..num_samples)
            .into_par_iter()
            .map(|t| compute_correlation(&model, &traces.column(t).to_owned()))
            .collect();

        let max_corr = correlations
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        if max_corr.abs() > best_corr.abs() {
            best_corr = max_corr;
            best_key = key_guess;
        }
    }
    best_key
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
 
    let filename = if args.len() == 1 {
        "src/trace_data_bootcamp_PT5000.csv"
    } else {
        &args[1]
    };

    let (plaintexts, _ciphertexts, traces) = read_trace_file(filename);

    let recovered_key_byte = compute_cpa(&plaintexts, &traces);
    println!("Recovered key byte: {:02X}", recovered_key_byte);
}
