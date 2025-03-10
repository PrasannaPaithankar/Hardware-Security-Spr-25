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
use plotly::{color::NamedColor, common::Marker, layout::Axis, Layout, Plot, Scatter, layout::Annotation};
use rayon::prelude::*;

// AES S-Box
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn hamming_weight(byte: u8) -> u8 {
    byte.count_ones() as u8
}

fn read_trace_file(
    filename: &str,
    window: (usize, usize),
) -> (Vec<String>, Vec<String>, Vec<Vec<f64>>) {
    let mut rdr = ReaderBuilder::new()
        .has_headers(true)
        .from_path(filename)
        .unwrap();

    let mut plaintexts: Vec<String> = Vec::new();
    let mut ciphertexts: Vec<String> = Vec::new();
    let mut traces: Vec<Vec<f64>> = Vec::new();

    for result in rdr.records() {
        let record = result.unwrap();
        plaintexts.push(record[0].to_string());
        ciphertexts.push(record[1].to_string());

        let trace: Vec<f64> = record
            .iter()
            .skip(2 + window.0)
            .take(window.1 - window.0) // Extracting the window of interest
            .map(|x| x.parse().unwrap())
            .collect();
        traces.push(trace);
    }

    (plaintexts, ciphertexts, traces)
}

// Parallel implementation of correlation matrix computation
fn compute_correlation_matrix(traces: &Vec<Vec<f64>>, plaintexts: &Vec<String>) -> Vec<Vec<f64>> {
    let num_traces = traces.len();
    let num_samples = traces[0].len();

    (0..256)
        .into_par_iter()
        .map(|key_byte| {
            println!("Processing guess key byte: {}", key_byte);
            (0..num_samples)
                .into_par_iter()
                .map(|poi| {
                    let hypo_vector: Vec<f64> = (0..num_traces)
                        .into_par_iter()
                        .map(|i| {
                            let pt = u128::from_str_radix(&plaintexts[i], 16).unwrap();
                            let pt_temp = ((pt >> 120) & 0xFF) as u8;
                            let btemp = SBOX[(pt_temp ^ key_byte as u8) as usize];
                            hamming_weight(btemp) as f64
                        })
                        .collect();

                    let pt_vector: Vec<f64> = traces.par_iter().map(|x| x[poi]).collect();
                    pearson_correlation(&hypo_vector, &pt_vector)
                })
                .collect()
        })
        .collect()
}

fn pearson_correlation(x: &Vec<f64>, y: &Vec<f64>) -> f64 {
    let n = x.len() as f64;
    let sum_x: f64 = x.iter().sum();
    let sum_y: f64 = y.iter().sum();
    let sum_x_sq: f64 = x.iter().map(|x| x * x).sum();
    let sum_y_sq: f64 = y.iter().map(|y| y * y).sum();
    let sum_xy: f64 = x.iter().zip(y.iter()).map(|(x, y)| x * y).sum();

    let numerator = n * sum_xy - sum_x * sum_y;
    let denominator = (n * sum_x_sq - sum_x * sum_x) * (n * sum_y_sq - sum_y * sum_y);
    let denominator = denominator.sqrt();

    (numerator / denominator).abs()
}

fn best_key_guess(correlations: &Vec<Vec<f64>>) -> u8 {
    let mut best_key = 0;
    let mut max_correlation = 0.0;

    for (key, correlation) in correlations.iter().enumerate() {
        let max_correlation_byte = correlation.iter().cloned().fold(0.0, f64::max);
        if max_correlation_byte > max_correlation {
            max_correlation = max_correlation_byte;
            best_key = key as u8;
        }
    }

    best_key
}

fn plot_correlation(correlations: &Vec<Vec<f64>>, key: u8, window: (usize, usize)) {
    let mut traces = Vec::new();
    for i in 0..correlations.len() {
        let trace = Scatter::new(
            (0..correlations[i].len()).collect::<Vec<usize>>(),
            correlations[i].clone(),
        );
        traces.push(trace);
    }

    let mut plot = Plot::new();
    for (i, trace) in traces.into_iter().enumerate() {
        if i == key as usize {
            plot.add_trace(trace.marker(Marker::new().color(NamedColor::Red)));
        } else {
            plot.add_trace(trace);
        }
    }

    let tick_values: Vec<f64> = (0..correlations[0].len()).map(|x| x as f64).collect();
    let tick_text: Vec<String> = (window.0..window.1).map(|x| x.to_string()).collect();

    plot.set_layout(
        Layout::new()
            .title("Trace Correlation")
            .x_axis(Axis::new()
                .title("Sample Number")
                .tick_values(tick_values)
                .tick_text(tick_text)
            )
            .y_axis(Axis::new().title("abs(Correlation)"))
            .annotations(vec![
                Annotation::new()
                    .x(2)
                    .y(0.7)
                    .text(format!("Best key guess: 0x{:02X}", key))
                    .show_arrow(false),
            ]),
    );

    plot.show();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let filename = if args.len() == 1 {
        "src/trace_data_bootcamp_PT5000.csv"
    } else {
        &args[1]
    };

    let correlations;

    // Window for the trace data
    let window = (1300, 1350);

    
    let mut input = String::new();
    if std::path::Path::new("correlation_matrix.csv").exists() {
        println!("Precomputed correlation matrix found. Do you want to use it? (y/n)");

        std::io::stdin().read_line(&mut input).unwrap();
    }

    if input.trim() == "y" {
        println!("Using precomputed correlation matrix");
        correlations = ReaderBuilder::new()
            .has_headers(false)
            .from_path("correlation_matrix.csv")
            .unwrap()
            .into_records()
            .map(|record| record.unwrap().iter().map(|x| x.parse().unwrap()).collect())
            .collect();
    } else {
        let (plaintexts, _, traces) = read_trace_file(filename, window);

        correlations = compute_correlation_matrix(&traces, &plaintexts);

        let mut wtr = csv::Writer::from_path("correlation_matrix.csv").unwrap();
        for row in correlations.iter() {
            wtr.write_record(row.iter().map(|x| x.to_string())).unwrap();
        }
        wtr.flush().unwrap();
    }

    let key = best_key_guess(&correlations);
    println!("\nBest key guess: 0x{:02X}", key);

    plot_correlation(&correlations, key, window);
}
