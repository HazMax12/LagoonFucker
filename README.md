# LagoonFucker (Inspired by Doomsday Fucker)

LagoonFucker is a lightweight detection script designed to identify the presence of the Lagoon client within a running process. It operates by scanning process memory and analyzing strings for known signatures associated with the client.

## Overview

This project focuses on basic memory inspection techniques to determine whether a target process contains identifiable traces of the Lagoon client. It is intended as a simple and direct approach to signature-based detection.

## How It Works

The script performs the following steps:

- Enumerates running processes or targets a specific process  
- Reads accessible memory regions from the process  
- Extracts and analyzes strings from memory  
- Compares extracted data against known Lagoon-related signatures  

If a match is found, the process is flagged as containing the client.

## Output

The script returns one of the following results:

- `process clean`  
  Indicates that no Lagoon-related signatures were found in the scanned process  

- `Lagoon fucked`  
  Indicates that the Lagoon client was detected in the process memory  

## Acknowledgements

This project is inspired by Doomsday Fucker and follows a similar concept of detecting software through memory inspection techniques.


## Usage

Run the script using:

```powershell
powershell Set-ExecutionPolicy -Scope Process Bypass; Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/HazMax12/LagoonFucker/refs/heads/main/main.ps1)
```
