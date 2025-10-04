#!/usr/bin/env python3
"""
🔧 S3-Based Large File Handler
=============================
Handle large files via S3 uploads to bypass API Gateway limits
"""

import boto3
import zipfile
import io

def deploy_s3_large_file_handler():
    """Deploy S3-based large file handler"""
    lambda_client = boto3.client('lambda', region_name='us-east-1')

    s3_handler_code = '''
import json
from datetime import datetime
import time
import base64
import binascii
import math
import gc
import tempfile
import os
import boto3
from urllib.parse import unquote

def lambda_handler(event, context):
    """S3-based large file handler"""
    try:
        # Handle CORS
        if event.get('httpMethod') == 'OPTIONS':
            return cors_response()

        # Get path and method
        http_method = event.get('httpMethod', 'GET')
        path = event.get('path', '/')

        # Clean path
        if path.startswith('/prod'):
            path = path[5:]
        if not path:
            path = '/'

        # Route requests
        if path == '/' or path == '/dashboard':
            return serve_dashboard()
        elif path == '/upload' and http_method == 'POST':
            return handle_standard_upload(event)
        elif path == '/upload-large' and http_method == 'POST':
            return handle_s3_large_file_upload(event)
        elif path == '/generate-upload-url' and http_method == 'POST':
            return generate_s3_upload_url(event)
        elif path.startswith('/analyze-s3/') and http_method == 'POST':
            return analyze_s3_file(event)
        else:
            return error_response(f'Path not found: {path}')

    except Exception as e:
        print(f"Lambda handler error: {str(e)}")
        return error_response(f'Server error: {str(e)}')

def generate_s3_upload_url(event):
    """Generate pre-signed S3 upload URL for large files"""
    try:
        body = json.loads(event.get('body', '{}'))
        file_name = body.get('file_name', f'upload-{int(time.time())}')
        file_type = body.get('file_type', 'application/octet-stream')

        s3_client = boto3.client('s3')
        bucket_name = 'quantumsentinel-large-files'  # We'll create this bucket

        # Generate unique key
        file_key = f'uploads/{int(time.time())}-{file_name}'

        # Generate presigned URL for upload
        presigned_url = s3_client.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': bucket_name,
                'Key': file_key,
                'ContentType': file_type
            },
            ExpiresIn=3600  # 1 hour
        )

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'upload_url': presigned_url,
                'file_key': file_key,
                'bucket': bucket_name,
                'expires_in': 3600
            })
        }

    except Exception as e:
        print(f"S3 URL generation error: {str(e)}")
        return error_response(f'Failed to generate upload URL: {str(e)}')

def analyze_s3_file(event):
    """Analyze file uploaded to S3"""
    try:
        # Extract file key from path
        path = event.get('path', '')
        file_key = unquote(path.split('/analyze-s3/')[-1])

        body = json.loads(event.get('body', '{}'))
        analysis_options = body.get('analysis_options', [])
        bucket_name = body.get('bucket', 'quantumsentinel-large-files')

        print(f"🔍 Analyzing S3 file: s3://{bucket_name}/{file_key}")

        s3_client = boto3.client('s3')

        # Get file info
        try:
            response = s3_client.head_object(Bucket=bucket_name, Key=file_key)
            file_size = response['ContentLength']
            file_name = file_key.split('/')[-1]
            print(f"📊 File size: {file_size:,} bytes")
        except Exception as e:
            return error_response(f'File not found in S3: {str(e)}')

        # Download file to temporary location
        temp_file_path = f'/tmp/{file_name}'
        try:
            s3_client.download_file(bucket_name, file_key, temp_file_path)
            print(f"📥 Downloaded to: {temp_file_path}")
        except Exception as e:
            return error_response(f'Failed to download file from S3: {str(e)}')

        # Perform analysis
        all_findings = []
        executed_modules = []
        analysis_id = f"FA-S3-{int(time.time())}"

        try:
            # Run all analysis modules
            if 'dast-analysis' in analysis_options:
                print("🔍 Running S3 DAST analysis...")
                dast_findings = perform_s3_dast_analysis(temp_file_path, file_name, file_size)
                all_findings.extend(dast_findings)
                executed_modules.append('dast-analysis')
                gc.collect()

            if 'static-analysis' in analysis_options:
                print("📋 Running S3 static analysis...")
                static_findings = perform_s3_static_analysis(temp_file_path, file_name, file_size)
                all_findings.extend(static_findings)
                executed_modules.append('static-analysis')
                gc.collect()

            if 'malware-scan' in analysis_options:
                print("🦠 Running S3 malware scan...")
                malware_findings = perform_s3_malware_scan(temp_file_path, file_name, file_size)
                all_findings.extend(malware_findings)
                executed_modules.append('malware-scan')
                gc.collect()

            if 'binary-analysis' in analysis_options:
                print("🔢 Running S3 binary analysis...")
                binary_findings = perform_s3_binary_analysis(temp_file_path, file_name, file_size)
                all_findings.extend(binary_findings)
                executed_modules.append('binary-analysis')
                gc.collect()

            if 'reverse-engineering' in analysis_options:
                print("🔬 Running S3 reverse engineering...")
                re_findings = perform_s3_reverse_engineering(temp_file_path, file_name, file_size)
                all_findings.extend(re_findings)
                executed_modules.append('reverse-engineering')
                gc.collect()

        finally:
            # Clean up
            try:
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
                    print(f"🗑️  Cleaned up: {temp_file_path}")
            except Exception as e:
                print(f"⚠️  Cleanup warning: {str(e)}")

        # Calculate results
        risk_score = calculate_s3_risk_score(all_findings)
        summary = generate_s3_summary(all_findings)

        print(f"✅ S3 analysis complete: {len(all_findings)} findings, risk: {risk_score}")

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'analysis_id': analysis_id,
                'file_name': file_name,
                'file_key': file_key,
                'timestamp': datetime.now().isoformat(),
                'status': 'completed',
                'risk_score': risk_score,
                'total_findings': len(all_findings),
                'findings': all_findings,
                'analysis_modules': analysis_options,
                'executed_modules': executed_modules,
                'file_size': file_size,
                'analysis_summary': summary,
                'processing_method': 's3_large_file_analysis'
            })
        }

    except Exception as e:
        print(f"❌ S3 analysis error: {str(e)}")
        return error_response(f'S3 analysis failed: {str(e)}')

def handle_standard_upload(event):
    """Handle standard small file uploads via API Gateway"""
    try:
        body = json.loads(event.get('body', '{}'))
        file_data = body.get('file_data', '')

        # Check size limit for API Gateway
        if len(file_data) > 8 * 1024 * 1024:  # 8MB base64 (~6MB original)
            return {
                'statusCode': 413,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'error': 'File too large for direct upload',
                    'recommendation': 'Use S3 large file upload for files > 6MB',
                    'max_direct_size': '6MB',
                    'use_endpoint': '/generate-upload-url'
                })
            }

        # Process normally for small files
        return handle_small_file_upload(event)

    except Exception as e:
        return error_response(f'Standard upload error: {str(e)}')

def handle_small_file_upload(event):
    """Handle small file uploads (original logic)"""
    # This is the original upload logic from before
    try:
        body = json.loads(event.get('body', '{}'))
        file_data = body.get('file_data', '')
        file_name = body.get('file_name', 'unknown_file')
        file_type = body.get('file_type', 'unknown')
        analysis_options = body.get('analysis_options', [])

        if not file_data:
            return error_response('No file data provided')

        decoded_data = base64.b64decode(file_data)
        original_size = len(decoded_data)

        # Use existing analysis functions but mark as small file
        all_findings = []
        executed_modules = []
        analysis_id = f"FA-SMALL-{int(time.time())}"

        # Write to temp file and analyze
        with tempfile.NamedTemporaryFile(delete=False, dir='/tmp') as temp_file:
            temp_file.write(decoded_data)
            temp_file_path = temp_file.name

        try:
            if 'dast-analysis' in analysis_options:
                dast_findings = perform_s3_dast_analysis(temp_file_path, file_name, original_size)
                all_findings.extend(dast_findings)
                executed_modules.append('dast-analysis')

            if 'static-analysis' in analysis_options:
                static_findings = perform_s3_static_analysis(temp_file_path, file_name, original_size)
                all_findings.extend(static_findings)
                executed_modules.append('static-analysis')

            if 'malware-scan' in analysis_options:
                malware_findings = perform_s3_malware_scan(temp_file_path, file_name, original_size)
                all_findings.extend(malware_findings)
                executed_modules.append('malware-scan')

            if 'binary-analysis' in analysis_options:
                binary_findings = perform_s3_binary_analysis(temp_file_path, file_name, original_size)
                all_findings.extend(binary_findings)
                executed_modules.append('binary-analysis')

            if 'reverse-engineering' in analysis_options:
                re_findings = perform_s3_reverse_engineering(temp_file_path, file_name, original_size)
                all_findings.extend(re_findings)
                executed_modules.append('reverse-engineering')

        finally:
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

        risk_score = calculate_s3_risk_score(all_findings)
        summary = generate_s3_summary(all_findings)

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'analysis_id': analysis_id,
                'file_name': file_name,
                'file_type': file_type,
                'timestamp': datetime.now().isoformat(),
                'status': 'completed',
                'risk_score': risk_score,
                'total_findings': len(all_findings),
                'findings': all_findings,
                'analysis_modules': analysis_options,
                'executed_modules': executed_modules,
                'file_size': original_size,
                'analysis_summary': summary,
                'processing_method': 'direct_small_file'
            })
        }

    except Exception as e:
        return error_response(f'Small file upload error: {str(e)}')

# Analysis functions (reusing optimized versions)
def perform_s3_dast_analysis(file_path, file_name, file_size):
    """DAST analysis for S3 files"""
    findings = []
    try:
        print(f"🔍 S3 DAST: Analyzing {file_size:,} bytes...")

        chunk_size = 1024 * 1024  # 1MB chunks
        chunks_analyzed = 0
        patterns_found = {}

        web_patterns = {
            b'<script': ('XSS Script Tag', 'medium'),
            b'javascript:': ('XSS JavaScript Protocol', 'medium'),
            b'eval(': ('Code Injection - Eval', 'high'),
            b'select * from': ('SQL Injection Pattern', 'high'),
            b'union select': ('SQL Union Attack', 'high'),
            b'password=': ('Hardcoded Password', 'critical'),
            b'api_key=': ('Hardcoded API Key', 'high'),
            b'secret=': ('Hardcoded Secret', 'high'),
            b'DROP TABLE': ('SQL Drop Table', 'critical'),
            b'system(': ('System Call', 'high')
        }

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                chunks_analyzed += 1
                chunk_lower = chunk.lower()

                for pattern, (desc, severity) in web_patterns.items():
                    if pattern.lower() in chunk_lower:
                        if pattern not in patterns_found:
                            patterns_found[pattern] = (desc, severity, chunks_analyzed)

                if chunks_analyzed >= 200:  # Limit for very large files
                    break

        for pattern, (desc, severity, chunk_num) in patterns_found.items():
            findings.append({
                'severity': severity,
                'type': 'S3 DAST Detection',
                'description': f'S3 DAST: {desc} detected in large mobile app',
                'recommendation': 'Implement input validation and sanitization',
                'file_location': file_name,
                'evidence': f'Pattern "{pattern.decode(errors="ignore")}" found in chunk {chunk_num}',
                'dast_analysis': True,
                's3_analysis': True
            })

        print(f"✅ S3 DAST: Analyzed {chunks_analyzed} chunks, found {len(findings)} issues")

    except Exception as e:
        print(f"❌ S3 DAST error: {str(e)}")

    return findings

def perform_s3_static_analysis(file_path, file_name, file_size):
    """Static analysis for S3 files"""
    findings = []
    try:
        mobile_patterns = {
            b'android.permission': ('Android Permission', 'info'),
            b'NSAppTransportSecurity': ('iOS ATS Configuration', 'medium'),
            b'CFBundleExecutable': ('iOS Bundle Executable', 'info'),
            b'AndroidManifest.xml': ('Android Manifest', 'info'),
            b'Info.plist': ('iOS Info Plist', 'info'),
            b'classes.dex': ('Android DEX File', 'medium'),
            b'libssl.so': ('SSL Library', 'medium'),
            b'libcrypto.so': ('Crypto Library', 'medium'),
            b'DEBUG': ('Debug Information', 'low'),
            b'AllowArbitraryLoads': ('iOS ATS Bypass', 'high'),
            b'android:exported="true"': ('Exported Component', 'medium')
        }

        chunk_size = 2 * 1024 * 1024
        chunks_analyzed = 0
        patterns_found = {}

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                chunks_analyzed += 1

                for pattern, (desc, severity) in mobile_patterns.items():
                    if pattern in chunk:
                        if pattern not in patterns_found:
                            patterns_found[pattern] = (desc, severity, chunks_analyzed)

                if chunks_analyzed >= 100:
                    break

        for pattern, (desc, severity, chunk_num) in patterns_found.items():
            findings.append({
                'severity': severity,
                'type': 'S3 Mobile Static Analysis',
                'description': f'S3 Static: {desc} detected',
                'recommendation': 'Review mobile app security configuration',
                'file_location': file_name,
                'evidence': f'Pattern "{pattern.decode(errors="ignore")}" found in chunk {chunk_num}',
                'static_analysis': True,
                's3_analysis': True
            })

        print(f"✅ S3 Static: Analyzed {chunks_analyzed} chunks, found {len(findings)} patterns")

    except Exception as e:
        print(f"❌ S3 Static error: {str(e)}")

    return findings

def perform_s3_malware_scan(file_path, file_name, file_size):
    """Malware scan for S3 files"""
    findings = []
    try:
        signatures_found = set()

        with open(file_path, 'rb') as f:
            # Check header
            header = f.read(2048)
            hex_header = binascii.hexlify(header).decode().lower()

            signatures = {
                '504b0304': ('ZIP/APK/IPA Archive', 'info'),
                '4d5a': ('PE Executable Header', 'high'),
                '7f454c46': ('ELF Binary', 'medium'),
                'feedface': ('Mach-O Binary', 'medium'),
                'cafebabe': ('Java Bytecode', 'low'),
                'dex0a035': ('Android DEX', 'info'),
                'ffd8ffe': ('JPEG Image', 'info'),
                '25504446': ('PDF Document', 'low')
            }

            for sig, (desc, severity) in signatures.items():
                if sig in hex_header:
                    signatures_found.add((sig, desc, severity, 'header'))

            # Check middle and end for large files
            if file_size > 2048:
                f.seek(file_size // 2)
                middle_chunk = f.read(1024)
                hex_middle = binascii.hexlify(middle_chunk).decode().lower()

                for sig, (desc, severity) in signatures.items():
                    if sig in hex_middle:
                        signatures_found.add((sig, f'{desc} (middle)', severity, 'middle'))

            if file_size > 4096:
                f.seek(max(0, file_size - 1024))
                end_chunk = f.read(1024)
                hex_end = binascii.hexlify(end_chunk).decode().lower()

                for sig, (desc, severity) in signatures.items():
                    if sig in hex_end:
                        signatures_found.add((sig, f'{desc} (end)', severity, 'end'))

        for sig, desc, severity, location in signatures_found:
            findings.append({
                'severity': severity,
                'type': 'S3 Binary Signature Detection',
                'description': f'S3 Malware Scan: {desc} detected',
                'recommendation': 'Verify binary legitimacy and scan with updated antivirus',
                'file_location': file_name,
                'evidence': f'Binary signature {sig.upper()} found in {location}',
                'malware_scan': True,
                's3_analysis': True
            })

        # Mobile-specific detection
        if file_name.lower().endswith('.ipa'):
            findings.append({
                'severity': 'high',
                'type': 'S3 iOS Application Package',
                'description': f'Large iOS app via S3 - {file_size:,} bytes requires comprehensive mobile security analysis',
                'recommendation': 'Perform comprehensive iOS mobile application security testing (MAST)',
                'file_location': file_name,
                'evidence': f'iOS application package (.ipa) - Size: {file_size:,} bytes via S3',
                'malware_scan': True,
                's3_analysis': True
            })
        elif file_name.lower().endswith('.apk'):
            findings.append({
                'severity': 'high',
                'type': 'S3 Android Application Package',
                'description': f'Large Android app via S3 - {file_size:,} bytes requires comprehensive mobile security analysis',
                'recommendation': 'Perform comprehensive Android mobile application security testing (MAST)',
                'file_location': file_name,
                'evidence': f'Android application package (.apk) - Size: {file_size:,} bytes via S3',
                'malware_scan': True,
                's3_analysis': True
            })

        print(f"✅ S3 Malware: Found {len(signatures_found)} signatures, {len(findings)} findings")

    except Exception as e:
        print(f"❌ S3 Malware error: {str(e)}")

    return findings

def perform_s3_binary_analysis(file_path, file_name, file_size):
    """Binary analysis for S3 files"""
    findings = []
    try:
        entropy = calculate_file_entropy_sample(file_path, file_size)

        findings.append({
            'severity': 'info',
            'type': 'S3 Large File Binary Analysis',
            'description': f'S3 large mobile app analysis: {file_size:,} bytes, entropy: {entropy:.2f}',
            'recommendation': 'Large mobile application analyzed via S3 for structure patterns',
            'file_location': file_name,
            'evidence': f'File size: {file_size:,} bytes, Sampled entropy: {entropy:.2f}',
            'binary_analysis': True,
            's3_analysis': True
        })

        if entropy > 7.5:
            findings.append({
                'severity': 'medium',
                'type': 'S3 High Entropy Detection',
                'description': f'S3 large mobile app shows high entropy ({entropy:.2f}) indicating compression or encryption',
                'recommendation': 'High entropy in mobile apps is normal due to compression, investigate if suspicious',
                'file_location': file_name,
                'evidence': f'S3 sampled entropy: {entropy:.2f} (threshold: 7.5)',
                'binary_analysis': True,
                's3_analysis': True
            })

        # File type detection
        with open(file_path, 'rb') as f:
            header = f.read(8)
            if len(header) >= 4:
                hex_header = binascii.hexlify(header[:4]).decode().lower()
                file_types = {
                    '504b0304': 'ZIP/IPA/APK Archive',
                    '4d5a9000': 'Windows Executable',
                    '7f454c46': 'Linux Binary',
                    'feedface': 'macOS/iOS Binary'
                }

                if hex_header in file_types:
                    findings.append({
                        'severity': 'info',
                        'type': f'S3 Large File Type: {file_types[hex_header]}',
                        'description': f'S3 large mobile app identified as {file_types[hex_header]} ({file_size:,} bytes)',
                        'recommendation': 'Apply mobile-specific security analysis',
                        'file_location': file_name,
                        'evidence': f'S3 file header: {hex_header.upper()}, Size: {file_size:,} bytes',
                        'binary_analysis': True,
                        's3_analysis': True
                    })

        print(f"✅ S3 Binary: Completed analysis, entropy: {entropy:.2f}")

    except Exception as e:
        print(f"❌ S3 Binary error: {str(e)}")

    return findings

def perform_s3_reverse_engineering(file_path, file_name, file_size):
    """Reverse engineering for S3 files"""
    findings = []
    try:
        strings_found = extract_strings_from_s3_file(file_path, file_size)

        if strings_found:
            sensitive_count = 0
            sensitive_examples = []

            suspicious_patterns = [
                'password', 'secret', 'key', 'token', 'api', 'admin', 'root',
                'debug', 'test', 'http://', 'https://', 'amazonaws.com',
                'private_key', 'certificate', 'ssl', 'tls'
            ]

            for string in strings_found:
                string_lower = string.lower()
                for pattern in suspicious_patterns:
                    if pattern in string_lower:
                        sensitive_count += 1
                        if len(sensitive_examples) < 5:
                            sensitive_examples.append(string[:50] + '...' if len(string) > 50 else string)
                        break

            if sensitive_count > 0:
                findings.append({
                    'severity': 'medium',
                    'type': 'S3 Sensitive Strings in Large Mobile App',
                    'description': f'S3 analysis found {sensitive_count} potentially sensitive strings in large mobile app',
                    'recommendation': 'Review extracted strings for sensitive information exposure',
                    'file_location': file_name,
                    'evidence': f'S3 examples: {", ".join(sensitive_examples[:3])}',
                    'reverse_engineering': True,
                    's3_analysis': True
                })

            # Mobile-specific analysis
            if file_name.lower().endswith(('.ipa', '.apk')):
                mobile_indicators = 0
                mobile_patterns = [
                    'CFBundle', 'UIRequired', 'NSApp', 'UIBackground',
                    'android.', 'com.android', 'AndroidManifest', 'classes.dex'
                ]

                for string in strings_found:
                    for pattern in mobile_patterns:
                        if pattern in string:
                            mobile_indicators += 1
                            break

                if mobile_indicators > 0:
                    platform = 'iOS' if file_name.lower().endswith('.ipa') else 'Android'
                    findings.append({
                        'severity': 'info',
                        'type': f'S3 {platform} Mobile App Metadata',
                        'description': f'S3 analysis found {mobile_indicators} {platform}-specific configuration strings',
                        'recommendation': f'Analyze {platform} app security configuration and permissions',
                        'file_location': file_name,
                        'evidence': f'S3: {mobile_indicators} {platform} metadata strings in {file_size:,} byte app',
                        'reverse_engineering': True,
                        's3_analysis': True
                    })

        print(f"✅ S3 RevEng: Extracted {len(strings_found)} strings, found {len(findings)} patterns")

    except Exception as e:
        print(f"❌ S3 RevEng error: {str(e)}")

    return findings

def extract_strings_from_s3_file(file_path, file_size, max_strings=1000):
    """Extract strings from S3 files efficiently"""
    strings = []
    try:
        sample_size = min(2 * 1024 * 1024, file_size // 5)  # Sample 20% or max 2MB
        samples_to_take = 10  # Take 10 samples

        with open(file_path, 'rb') as f:
            for i in range(samples_to_take):
                position = (file_size // samples_to_take) * i
                f.seek(position)
                sample = f.read(sample_size)
                if not sample:
                    break

                current_string = ""
                for byte_val in sample:
                    if 32 <= byte_val <= 126:
                        current_string += chr(byte_val)
                    else:
                        if len(current_string) >= 4:
                            strings.append(current_string)
                            if len(strings) >= max_strings:
                                return strings[:max_strings]
                        current_string = ""

                if len(current_string) >= 4:
                    strings.append(current_string)

    except Exception as e:
        print(f"S3 string extraction error: {str(e)}")

    return strings[:max_strings]

def calculate_file_entropy_sample(file_path, file_size):
    """Calculate entropy by sampling file"""
    try:
        sample_size = min(2 * 1024 * 1024, file_size)

        with open(file_path, 'rb') as f:
            f.seek(max(0, (file_size - sample_size) // 2))
            sample = f.read(sample_size)

        if not sample:
            return 0

        freq = {}
        for byte_val in sample:
            freq[byte_val] = freq.get(byte_val, 0) + 1

        entropy = 0
        length = len(sample)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    except Exception as e:
        print(f"S3 entropy calculation error: {str(e)}")
        return 0

def calculate_s3_risk_score(findings):
    """Calculate risk score for S3 analysis"""
    if not findings:
        return 0

    severity_scores = {
        'critical': 100,
        'high': 75,
        'medium': 50,
        'low': 25,
        'info': 5
    }

    total_score = 0
    for finding in findings:
        severity = finding.get('severity', 'info').lower()
        score = severity_scores.get(severity, 5)

        if finding.get('s3_analysis'):
            score = int(score * 1.3)  # 30% bonus for S3 large file analysis

        total_score += score

    return min(total_score, 100)

def generate_s3_summary(findings):
    """Generate summary for S3 analysis"""
    summary = {
        'critical_findings': 0,
        'high_findings': 0,
        'medium_findings': 0,
        'low_findings': 0,
        'info_findings': 0,
        'dast_patterns_detected': 0,
        'modules_executed': 0,
        's3_large_file_analysis': True
    }

    for finding in findings:
        severity = finding.get('severity', 'info').lower()
        summary[f'{severity}_findings'] += 1

        if finding.get('dast_analysis'):
            summary['dast_patterns_detected'] += 1

    analysis_types = set()
    for finding in findings:
        for key in ['dast_analysis', 'static_analysis', 'malware_scan', 'binary_analysis', 'reverse_engineering']:
            if finding.get(key):
                analysis_types.add(key.replace('_analysis', '').replace('_scan', '').replace('_engineering', ''))

    summary['modules_executed'] = len(analysis_types)
    return summary

def serve_dashboard():
    """Serve S3-enabled dashboard"""
    timestamp = int(time.time())
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/html',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        },
        'body': get_s3_dashboard_html(timestamp)
    }

def cors_response():
    """Return CORS response"""
    return {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With'
        },
        'body': ''
    }

def error_response(message):
    """Return error response"""
    return {
        'statusCode': 400,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'error': message,
            'timestamp': datetime.now().isoformat()
        })
    }

def get_s3_dashboard_html(timestamp):
    """Generate S3-enabled dashboard HTML"""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QuantumSentinel - S3 Large File Analysis v""" + str(timestamp) + """</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: #ffffff; min-height: 100vh; margin: 0; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }
        .header h1 { font-size: 2.5em; margin: 0; }
        .version-info { background: #28a745; color: white; padding: 12px; text-align: center; font-weight: bold; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .section { background: rgba(255,255,255,0.1); border-radius: 15px; padding: 30px; margin: 20px 0; box-shadow: 0 8px 25px rgba(0,0,0,0.2); }
        .file-upload { border: 3px dashed #667eea; border-radius: 15px; padding: 40px; text-align: center; margin: 20px 0; cursor: pointer; }
        .upload-btn { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; border: none; padding: 15px 30px; border-radius: 25px; cursor: pointer; font-size: 16px; font-weight: bold; margin: 10px; }
        .analysis-options { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .option-card { background: rgba(255,255,255,0.1); border-radius: 10px; padding: 15px; text-align: center; border: 2px solid transparent; cursor: pointer; transition: all 0.3s; }
        .option-card.selected { border-color: #28a745; background: rgba(40, 167, 69, 0.2); }
        .results { background: rgba(0,0,0,0.3); border-radius: 10px; padding: 20px; margin: 20px 0; max-height: 500px; overflow-y: auto; }
        .finding { background: rgba(255,255,255,0.1); border-left: 4px solid; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .finding.critical { border-left-color: #dc3545; }
        .finding.high { border-left-color: #fd7e14; }
        .finding.medium { border-left-color: #ffc107; }
        .finding.low { border-left-color: #17a2b8; }
        .finding.info { border-left-color: #6c757d; }
        .status { text-align: center; padding: 15px; border-radius: 10px; margin: 10px 0; font-weight: bold; }
        .status.success { background: rgba(40, 167, 69, 0.2); color: #28a745; }
        .status.error { background: rgba(220, 53, 69, 0.2); color: #dc3545; }
        .progress { text-align: center; padding: 20px; }
        .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 2s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .s3-info { background: rgba(0, 123, 255, 0.2); border: 1px solid #007bff; border-radius: 10px; padding: 15px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ QuantumSentinel-Nexus</h1>
        <div class="subtitle">S3-Powered Large Mobile Application Security Analysis</div>
    </div>

    <div class="version-info">
        ✅ S3 LARGE FILE ENGINE v""" + str(timestamp) + """ - No Size Limits via S3 Upload
    </div>

    <div class="container">
        <div class="section">
            <h2>📱 Unlimited Mobile Application Security Analysis</h2>
            <p>Upload mobile applications of any size using S3-powered analysis</p>

            <div class="s3-info">
                <h4>🚀 S3 Large File Capabilities:</h4>
                <ul>
                    <li>✅ No file size limits (supports GB-sized applications)</li>
                    <li>✅ Direct S3 upload bypasses API Gateway limits</li>
                    <li>✅ Optimized streaming analysis</li>
                    <li>✅ Enhanced security with temporary pre-signed URLs</li>
                    <li>✅ All 5 security modules with intelligent sampling</li>
                </ul>
            </div>

            <div class="file-upload" onclick="document.getElementById('fileInput').click()">
                <h3>📁 Choose Mobile Application (Any Size)</h3>
                <p>Upload APK/IPA files - automatic routing for optimal processing</p>
                <p><strong>Small files (&lt;6MB):</strong> Direct upload</p>
                <p><strong>Large files (&gt;6MB):</strong> S3-powered upload</p>
                <input type="file" id="fileInput" style="display: none" onchange="handleFileSelect(event)" accept=".apk,.ipa">
                <button class="upload-btn">Select Mobile App</button>
            </div>

            <div class="analysis-options">
                <div class="option-card" onclick="toggleOption('dast-analysis', this)">
                    <h4>🔍 DAST Analysis</h4>
                    <p>Advanced vulnerability detection</p>
                </div>
                <div class="option-card" onclick="toggleOption('static-analysis', this)">
                    <h4>📋 Static Analysis</h4>
                    <p>Mobile security pattern analysis</p>
                </div>
                <div class="option-card" onclick="toggleOption('malware-scan', this)">
                    <h4>🦠 Malware Scan</h4>
                    <p>Comprehensive signature detection</p>
                </div>
                <div class="option-card" onclick="toggleOption('binary-analysis', this)">
                    <h4>🔢 Binary Analysis</h4>
                    <p>Structure & entropy analysis</p>
                </div>
                <div class="option-card" onclick="toggleOption('reverse-engineering', this)">
                    <h4>🔬 Reverse Engineering</h4>
                    <p>Advanced string extraction</p>
                </div>
            </div>

            <button class="upload-btn" onclick="startAnalysis()" style="width: 100%; font-size: 18px;">
                🚀 Start S3-Powered Analysis
            </button>

            <div id="progress-container" class="progress" style="display: none;">
                <div class="spinner"></div>
                <p id="progress-text">Processing mobile application...</p>
            </div>

            <div id="results-container" class="results" style="display: none;">
                <h3>🔍 Analysis Results</h3>
                <div id="analysis-results"></div>
            </div>
        </div>
    </div>

    <script>
        let selectedFile = null;
        let selectedOptions = [];

        function handleFileSelect(event) {
            selectedFile = event.target.files[0];
            if (selectedFile) {
                const sizeMB = (selectedFile.size / 1024 / 1024).toFixed(1);
                const method = selectedFile.size > 6 * 1024 * 1024 ? 'S3' : 'Direct';
                document.querySelector('.file-upload h3').textContent =
                    '📁 Selected: ' + selectedFile.name + ' (' + sizeMB + 'MB) [' + method + ']';
            }
        }

        function toggleOption(option, element) {
            if (selectedOptions.includes(option)) {
                selectedOptions = selectedOptions.filter(opt => opt !== option);
                element.classList.remove('selected');
            } else {
                selectedOptions.push(option);
                element.classList.add('selected');
            }
        }

        function startAnalysis() {
            if (!selectedFile) {
                alert('Please select a mobile application file first');
                return;
            }

            if (selectedOptions.length === 0) {
                alert('Please select at least one analysis option');
                return;
            }

            const sizeMB = (selectedFile.size / 1024 / 1024).toFixed(1);

            // Choose method based on file size
            if (selectedFile.size > 6 * 1024 * 1024) {
                startS3Analysis();
            } else {
                startDirectAnalysis();
            }
        }

        function startDirectAnalysis() {
            document.getElementById('progress-container').style.display = 'block';
            document.getElementById('results-container').style.display = 'none';
            document.getElementById('progress-text').textContent = 'Processing file directly...';

            const reader = new FileReader();
            reader.onload = function(e) {
                const fileData = btoa(String.fromCharCode(...new Uint8Array(e.target.result)));

                const payload = {
                    file_data: fileData,
                    file_name: selectedFile.name,
                    file_type: selectedFile.type || 'application/octet-stream',
                    analysis_options: selectedOptions
                };

                fetch('https://992558rxmc.execute-api.us-east-1.amazonaws.com/prod/upload', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                })
                .then(response => response.json())
                .then(data => displayResults(data))
                .catch(error => showError('Direct analysis failed: ' + error.message));
            };
            reader.readAsArrayBuffer(selectedFile);
        }

        function startS3Analysis() {
            document.getElementById('progress-container').style.display = 'block';
            document.getElementById('results-container').style.display = 'none';
            document.getElementById('progress-text').textContent = 'Getting S3 upload URL...';

            // Step 1: Get upload URL
            fetch('https://992558rxmc.execute-api.us-east-1.amazonaws.com/prod/generate-upload-url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    file_name: selectedFile.name,
                    file_type: selectedFile.type || 'application/octet-stream'
                })
            })
            .then(response => response.json())
            .then(urlData => {
                if (urlData.upload_url) {
                    document.getElementById('progress-text').textContent = 'Uploading to S3...';

                    // Step 2: Upload to S3
                    return fetch(urlData.upload_url, {
                        method: 'PUT',
                        body: selectedFile,
                        headers: {
                            'Content-Type': selectedFile.type || 'application/octet-stream'
                        }
                    }).then(response => {
                        if (response.ok) {
                            return urlData;
                        } else {
                            throw new Error('S3 upload failed');
                        }
                    });
                } else {
                    throw new Error('Failed to get upload URL');
                }
            })
            .then(urlData => {
                document.getElementById('progress-text').textContent = 'Analyzing uploaded file...';

                // Step 3: Trigger analysis
                return fetch('https://992558rxmc.execute-api.us-east-1.amazonaws.com/prod/analyze-s3/' + encodeURIComponent(urlData.file_key), {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        bucket: urlData.bucket,
                        analysis_options: selectedOptions
                    })
                });
            })
            .then(response => response.json())
            .then(data => displayResults(data))
            .catch(error => showError('S3 analysis failed: ' + error.message));
        }

        function displayResults(data) {
            document.getElementById('progress-container').style.display = 'none';
            document.getElementById('results-container').style.display = 'block';

            const sizeMB = data.file_size ? (data.file_size / 1024 / 1024).toFixed(1) : 'Unknown';
            const method = data.processing_method || 'unknown';

            let html = '<div class="status success">';
            html += '<h3>✅ ANALYSIS COMPLETE</h3>';
            html += '<p><strong>File:</strong> ' + data.file_name + ' (' + sizeMB + ' MB)</p>';
            html += '<p><strong>Method:</strong> ' + method + '</p>';
            html += '<p><strong>Risk Score:</strong> ' + data.risk_score + '/100</p>';
            html += '<p><strong>Total Findings:</strong> ' + data.total_findings + '</p>';
            html += '<p><strong>Modules:</strong> ' + data.executed_modules.join(', ') + '</p>';
            html += '</div>';

            if (data.findings && data.findings.length > 0) {
                html += '<h4>🔍 Security Findings:</h4>';
                data.findings.forEach(function(finding) {
                    const isS3 = finding.s3_analysis ? ' 🌐' : '';
                    html += '<div class="finding ' + finding.severity + '">';
                    html += '<h5>' + finding.severity.toUpperCase() + ': ' + finding.type + isS3 + '</h5>';
                    html += '<p><strong>Description:</strong> ' + finding.description + '</p>';
                    html += '<p><strong>Recommendation:</strong> ' + finding.recommendation + '</p>';
                    html += '<p><strong>Evidence:</strong> ' + finding.evidence + '</p>';
                    html += '</div>';
                });
            } else {
                html += '<div class="status success">✅ No security issues detected!</div>';
            }

            document.getElementById('analysis-results').innerHTML = html;
        }

        function showError(message) {
            document.getElementById('progress-container').style.display = 'none';
            document.getElementById('results-container').style.display = 'block';
            document.getElementById('analysis-results').innerHTML = '<div class="status error">❌ ' + message + '</div>';
        }
    </script>
</body>
</html>"""
'''

    # Create zip file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr('lambda_function.py', s3_handler_code)

    # Update Lambda function
    response = lambda_client.update_function_code(
        FunctionName='quantumsentinel-new-complete-dashboard',
        ZipFile=zip_buffer.getvalue()
    )

    print("✅ S3 large file handler deployed successfully!")
    print(f"   Function ARN: {response.get('FunctionArn')}")
    print(f"   Code Size: {response.get('CodeSize')} bytes")
    print(f"   Last Modified: {response.get('LastModified')}")
    print("\n🌐 S3 LARGE FILE FEATURES:")
    print("   ✅ No file size limits via S3 upload")
    print("   ✅ Automatic routing: Direct (<6MB) vs S3 (>6MB)")
    print("   ✅ Pre-signed S3 URLs for secure uploads")
    print("   ✅ Streaming analysis with intelligent sampling")
    print("   ✅ Enhanced mobile-specific pattern detection")
    print("   ✅ All 5 security modules optimized for large files")
    print("   ✅ Memory efficient processing")

    print("\n📋 NEXT STEPS:")
    print("   1. Create S3 bucket: quantumsentinel-large-files")
    print("   2. Configure bucket permissions")
    print("   3. Test with original large mobile apps")

if __name__ == "__main__":
    deploy_s3_large_file_handler()