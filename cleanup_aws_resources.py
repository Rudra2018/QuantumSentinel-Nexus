#!/usr/bin/env python3
"""
🧹 AWS Resource Cleanup Script
Clean up existing QuantumSentinel resources before deploying unified platform
"""

import boto3
import json
import time
from botocore.exceptions import ClientError

class AWSResourceCleaner:
    def __init__(self):
        self.s3 = boto3.client('s3', region_name='us-east-1')
        self.lambda_client = boto3.client('lambda', region_name='us-east-1')
        self.apigateway = boto3.client('apigateway', region_name='us-east-1')

    def cleanup_s3_buckets(self):
        """Clean up old S3 buckets except the main ones"""
        print("🧹 Cleaning up S3 buckets...")

        # Buckets to keep
        keep_buckets = [
            'quantumsentinel-large-files',
            'quantumsentinel-unified-dashboard'
        ]

        # Buckets to delete
        delete_buckets = [
            'quantumsentinel-nexus-077732578302-1759302532',
            'quantumsentinel-nexus-quantum-configs-077732578302',
            'quantumsentinel-nexus-quantum-evidence-077732578302',
            'quantumsentinel-nexus-quantum-logs-077732578302',
            'quantumsentinel-nexus-quantum-ml-models-077732578302',
            'quantumsentinel-nexus-quantum-reports-077732578302',
            'quantumsentinel-nexus-quantum-research-data-077732578302'
        ]

        for bucket_name in delete_buckets:
            try:
                # Empty bucket first
                print(f"  🗑️ Emptying bucket: {bucket_name}")
                self._empty_bucket(bucket_name)

                # Delete bucket
                print(f"  ❌ Deleting bucket: {bucket_name}")
                self.s3.delete_bucket(Bucket=bucket_name)
                print(f"  ✅ Deleted bucket: {bucket_name}")

            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucket':
                    print(f"  ℹ️ Bucket already deleted: {bucket_name}")
                else:
                    print(f"  ❌ Error deleting bucket {bucket_name}: {e}")

    def _empty_bucket(self, bucket_name):
        """Empty all objects from bucket"""
        try:
            response = self.s3.list_objects_v2(Bucket=bucket_name)
            if 'Contents' in response:
                objects = [{'Key': obj['Key']} for obj in response['Contents']]
                self.s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={'Objects': objects}
                )
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucket':
                print(f"    ⚠️ Error emptying bucket: {e}")

    def cleanup_lambda_functions(self):
        """Clean up old Lambda functions"""
        print("\n🧹 Cleaning up Lambda functions...")

        # Functions to keep for new unified platform
        keep_functions = [
            'quantumsentinel-nexus-api'
        ]

        # Functions to delete
        delete_functions = [
            'quantumsentinel-sast-engine',
            'quantumsentinel-url-scanner',
            'quantumsentinel-bug-bounty-automation',
            'quantumsentinel-agentic-ai',
            'quantumsentinel-reverse-engineering',
            'quantumsentinel-unified-dashboard',
            'quantumsentinel-dast-engine',
            'quantumsentinel-web-dashboard',
            'quantumsentinel-frida-instrumentation',
            'quantumsentinel-new-complete-dashboard',
            'quantumsentinel-dashboard-api',
            'quantumsentinel-binary-analysis'
        ]

        for function_name in delete_functions:
            try:
                print(f"  ❌ Deleting function: {function_name}")
                self.lambda_client.delete_function(FunctionName=function_name)
                print(f"  ✅ Deleted function: {function_name}")
                time.sleep(1)  # Rate limiting

            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    print(f"  ℹ️ Function already deleted: {function_name}")
                else:
                    print(f"  ❌ Error deleting function {function_name}: {e}")

    def cleanup_api_gateways(self):
        """Clean up old API Gateways"""
        print("\n🧹 Cleaning up API Gateways...")

        # APIs to delete
        delete_apis = [
            '2p83ibp3ai',  # quantumsentinel-nexus-api
            '992558rxmc'   # quantumsentinel-new-complete-api
        ]

        for api_id in delete_apis:
            try:
                print(f"  ❌ Deleting API Gateway: {api_id}")
                self.apigateway.delete_rest_api(restApiId=api_id)
                print(f"  ✅ Deleted API Gateway: {api_id}")
                time.sleep(2)  # Rate limiting

            except ClientError as e:
                if e.response['Error']['Code'] == 'NotFoundException':
                    print(f"  ℹ️ API Gateway already deleted: {api_id}")
                else:
                    print(f"  ❌ Error deleting API Gateway {api_id}: {e}")

    def run_cleanup(self):
        """Run complete cleanup"""
        print("🚀 STARTING AWS RESOURCE CLEANUP")
        print("=" * 50)

        # Clean up resources
        self.cleanup_lambda_functions()
        self.cleanup_api_gateways()
        self.cleanup_s3_buckets()

        print("\n✅ CLEANUP COMPLETE")
        print("Remaining resources for unified platform:")
        print("  • quantumsentinel-large-files (S3)")
        print("  • quantumsentinel-unified-dashboard (S3)")
        print("  • quantumsentinel-nexus-api (Lambda - kept for base API)")

def main():
    """Main cleanup function"""
    cleaner = AWSResourceCleaner()
    cleaner.run_cleanup()

if __name__ == "__main__":
    main()