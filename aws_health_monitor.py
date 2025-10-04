#!/usr/bin/env python3
"""
🌐 QuantumSentinel AWS Health Monitor
====================================
Comprehensive health monitoring for all AWS modules
"""

import boto3
import json
import time
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

class AWSHealthMonitor:
    def __init__(self):
        self.aws_region = 'us-east-1'
        self.account_id = '077732578302'

        # AWS Clients
        self.lambda_client = boto3.client('lambda', region_name=self.aws_region)
        self.ecs_client = boto3.client('ecs', region_name=self.aws_region)
        self.ec2_client = boto3.client('ec2', region_name=self.aws_region)
        self.apigateway_client = boto3.client('apigateway', region_name=self.aws_region)
        self.cloudwatch_client = boto3.client('cloudwatch', region_name=self.aws_region)

        # Module configurations
        self.modules = {
            'lambda_functions': [
                'quantumsentinel-web-dashboard',
                'quantumsentinel-binary-analysis',
                'quantumsentinel-unified-dashboard'
            ],
            'ecs_tasks': [
                'quantumsentinel-web-ui',
                'quantumsentinel-binary-analysis',
                'quantumsentinel-ibb-research'
            ],
            'api_endpoints': [
                'https://ex57j8i2bi.execute-api.us-east-1.amazonaws.com/prod',
                'https://ex57j8i2bi.execute-api.us-east-1.amazonaws.com/prod/reverse-engineering',
                'https://ex57j8i2bi.execute-api.us-east-1.amazonaws.com/prod/sast',
                'https://ex57j8i2bi.execute-api.us-east-1.amazonaws.com/prod/dast',
                'https://ex57j8i2bi.execute-api.us-east-1.amazonaws.com/prod/ai',
                'https://ex57j8i2bi.execute-api.us-east-1.amazonaws.com/prod/frida',
                'https://ex57j8i2bi.execute-api.us-east-1.amazonaws.com/prod/bugbounty'
            ]
        }

        self.health_status = {}
        self.lock = threading.Lock()

    def check_lambda_health(self, function_name):
        """Check Lambda function health"""
        try:
            response = self.lambda_client.get_function(FunctionName=function_name)
            config = self.lambda_client.get_function_configuration(FunctionName=function_name)

            # Try to invoke the function for a basic health check
            try:
                invoke_response = self.lambda_client.invoke(
                    FunctionName=function_name,
                    InvocationType='RequestResponse',
                    Payload=json.dumps({'health_check': True})
                )
                invocation_success = invoke_response['StatusCode'] == 200
            except:
                invocation_success = False

            return {
                'name': function_name,
                'status': 'HEALTHY' if invocation_success else 'DEGRADED',
                'state': config['State'],
                'last_modified': config['LastModified'],
                'runtime': config['Runtime'],
                'memory': config['MemorySize'],
                'timeout': config['Timeout'],
                'invocation_test': invocation_success
            }
        except Exception as e:
            return {
                'name': function_name,
                'status': 'UNHEALTHY',
                'error': str(e),
                'invocation_test': False
            }

    def check_ecs_health(self, task_definition):
        """Check ECS task health"""
        try:
            # Get task definition
            response = self.ecs_client.describe_task_definition(
                taskDefinition=task_definition
            )

            # List running tasks
            clusters = self.ecs_client.list_clusters()
            running_tasks = 0

            for cluster in clusters.get('clusterArns', []):
                tasks = self.ecs_client.list_tasks(
                    cluster=cluster,
                    family=task_definition
                )
                running_tasks += len(tasks.get('taskArns', []))

            return {
                'name': task_definition,
                'status': 'HEALTHY' if running_tasks > 0 else 'DEGRADED',
                'running_tasks': running_tasks,
                'revision': response['taskDefinition']['revision'],
                'cpu': response['taskDefinition']['cpu'],
                'memory': response['taskDefinition']['memory']
            }
        except Exception as e:
            return {
                'name': task_definition,
                'status': 'UNHEALTHY',
                'error': str(e),
                'running_tasks': 0
            }

    def check_api_endpoint_health(self, endpoint):
        """Check API Gateway endpoint health"""
        try:
            response = requests.get(endpoint, timeout=10)

            return {
                'endpoint': endpoint,
                'status': 'HEALTHY' if response.status_code == 200 else 'DEGRADED',
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'response_size': len(response.content)
            }
        except Exception as e:
            return {
                'endpoint': endpoint,
                'status': 'UNHEALTHY',
                'error': str(e),
                'status_code': None,
                'response_time': None
            }

    def get_cloudwatch_metrics(self):
        """Get CloudWatch metrics for monitoring"""
        try:
            # Get Lambda metrics
            lambda_metrics = self.cloudwatch_client.get_metric_statistics(
                Namespace='AWS/Lambda',
                MetricName='Invocations',
                Dimensions=[],
                StartTime=datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0),
                EndTime=datetime.utcnow(),
                Period=3600,
                Statistics=['Sum']
            )

            # Get API Gateway metrics
            api_metrics = self.cloudwatch_client.get_metric_statistics(
                Namespace='AWS/ApiGateway',
                MetricName='Count',
                Dimensions=[],
                StartTime=datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0),
                EndTime=datetime.utcnow(),
                Period=3600,
                Statistics=['Sum']
            )

            return {
                'lambda_invocations': sum([point['Sum'] for point in lambda_metrics['Datapoints']]),
                'api_requests': sum([point['Sum'] for point in api_metrics['Datapoints']])
            }
        except Exception as e:
            return {
                'lambda_invocations': 0,
                'api_requests': 0,
                'error': str(e)
            }

    def run_comprehensive_health_check(self):
        """Run comprehensive health check on all modules"""
        print("🔍 Starting comprehensive AWS health check...")

        health_report = {
            'timestamp': datetime.now().isoformat(),
            'lambda_functions': [],
            'ecs_tasks': [],
            'api_endpoints': [],
            'cloudwatch_metrics': {},
            'overall_status': 'UNKNOWN'
        }

        # Check Lambda functions
        print("\n📋 Checking Lambda Functions...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            lambda_futures = {
                executor.submit(self.check_lambda_health, func): func
                for func in self.modules['lambda_functions']
            }

            for future in as_completed(lambda_futures):
                result = future.result()
                health_report['lambda_functions'].append(result)
                status = "✅" if result['status'] == 'HEALTHY' else "⚠️" if result['status'] == 'DEGRADED' else "❌"
                print(f"   {status} {result['name']}: {result['status']}")

        # Check ECS tasks
        print("\n🐳 Checking ECS Tasks...")
        with ThreadPoolExecutor(max_workers=3) as executor:
            ecs_futures = {
                executor.submit(self.check_ecs_health, task): task
                for task in self.modules['ecs_tasks']
            }

            for future in as_completed(ecs_futures):
                result = future.result()
                health_report['ecs_tasks'].append(result)
                status = "✅" if result['status'] == 'HEALTHY' else "⚠️" if result['status'] == 'DEGRADED' else "❌"
                print(f"   {status} {result['name']}: {result['status']} ({result.get('running_tasks', 0)} tasks)")

        # Check API endpoints
        print("\n🌐 Checking API Endpoints...")
        with ThreadPoolExecutor(max_workers=7) as executor:
            api_futures = {
                executor.submit(self.check_api_endpoint_health, endpoint): endpoint
                for endpoint in self.modules['api_endpoints']
            }

            for future in as_completed(api_futures):
                result = future.result()
                health_report['api_endpoints'].append(result)
                status = "✅" if result['status'] == 'HEALTHY' else "⚠️" if result['status'] == 'DEGRADED' else "❌"
                endpoint_name = result['endpoint'].split('/')[-1] or 'dashboard'
                print(f"   {status} {endpoint_name}: {result['status']} ({result.get('response_time', 'N/A')}s)")

        # Get CloudWatch metrics
        print("\n📊 Collecting CloudWatch Metrics...")
        health_report['cloudwatch_metrics'] = self.get_cloudwatch_metrics()

        # Calculate overall status
        all_statuses = []
        all_statuses.extend([item['status'] for item in health_report['lambda_functions']])
        all_statuses.extend([item['status'] for item in health_report['ecs_tasks']])
        all_statuses.extend([item['status'] for item in health_report['api_endpoints']])

        if all(status == 'HEALTHY' for status in all_statuses):
            health_report['overall_status'] = 'HEALTHY'
        elif any(status == 'UNHEALTHY' for status in all_statuses):
            health_report['overall_status'] = 'UNHEALTHY'
        else:
            health_report['overall_status'] = 'DEGRADED'

        return health_report

    def display_health_dashboard(self, health_report):
        """Display comprehensive health dashboard"""
        print("\n" + "="*70)
        print("🌐 QUANTUMSENTINEL AWS HEALTH DASHBOARD")
        print("="*70)

        overall_icon = "✅" if health_report['overall_status'] == 'HEALTHY' else "⚠️" if health_report['overall_status'] == 'DEGRADED' else "❌"
        print(f"\n{overall_icon} OVERALL STATUS: {health_report['overall_status']}")
        print(f"🕒 Last Check: {health_report['timestamp']}")

        # Summary counts
        lambda_healthy = sum(1 for item in health_report['lambda_functions'] if item['status'] == 'HEALTHY')
        ecs_healthy = sum(1 for item in health_report['ecs_tasks'] if item['status'] == 'HEALTHY')
        api_healthy = sum(1 for item in health_report['api_endpoints'] if item['status'] == 'HEALTHY')

        print(f"\n📊 HEALTH SUMMARY:")
        print(f"   Lambda Functions: {lambda_healthy}/{len(health_report['lambda_functions'])} healthy")
        print(f"   ECS Tasks: {ecs_healthy}/{len(health_report['ecs_tasks'])} healthy")
        print(f"   API Endpoints: {api_healthy}/{len(health_report['api_endpoints'])} healthy")

        # CloudWatch metrics
        metrics = health_report['cloudwatch_metrics']
        print(f"\n📈 USAGE METRICS (Today):")
        print(f"   Lambda Invocations: {metrics.get('lambda_invocations', 0)}")
        print(f"   API Requests: {metrics.get('api_requests', 0)}")

        print("\n" + "="*70)

        return health_report

    def save_health_report(self, health_report, filename=None):
        """Save health report to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"aws_health_report_{timestamp}.json"

        with open(filename, 'w') as f:
            json.dump(health_report, f, indent=2, default=str)

        print(f"💾 Health report saved to: {filename}")
        return filename

    def continuous_monitoring(self, interval=300):
        """Run continuous health monitoring"""
        print(f"🔄 Starting continuous monitoring (every {interval} seconds)...")

        try:
            while True:
                health_report = self.run_comprehensive_health_check()
                self.display_health_dashboard(health_report)

                # Save report if there are issues
                if health_report['overall_status'] != 'HEALTHY':
                    self.save_health_report(health_report)

                print(f"\n⏰ Next check in {interval} seconds... (Ctrl+C to stop)")
                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped by user")

def main():
    """Main function"""
    monitor = AWSHealthMonitor()

    # Run single health check
    health_report = monitor.run_comprehensive_health_check()
    monitor.display_health_dashboard(health_report)

    # Save the report
    report_file = monitor.save_health_report(health_report)

    # Ask if user wants continuous monitoring
    print(f"\n🔄 Would you like to start continuous monitoring? (y/n): ", end="")
    try:
        choice = input().lower().strip()
        if choice in ['y', 'yes']:
            monitor.continuous_monitoring()
    except (EOFError, KeyboardInterrupt):
        print("\n👋 Goodbye!")

if __name__ == "__main__":
    main()