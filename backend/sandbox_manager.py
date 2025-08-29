"""
Sandbox Management System
Phase 4: Safe APK Execution Environment
"""

import os
import json
import docker
import tempfile
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import threading
import time

class SandboxManager:
    """Manages isolated sandbox environments for APK execution"""
    
    def __init__(self):
        self.docker_client = None
        self.active_containers = {}
        self.sandbox_configs = {
            'android_emulator': {
                'image': 'budtmo/docker-android:emulator_11.0',
                'ports': {'5554/tcp': 5554, '5555/tcp': 5555},
                'environment': {
                    'EMULATOR_DEVICE': 'Samsung Galaxy S10',
                    'WEB_VNC': 'true',
                    'APPIUM': 'true'
                },
                'volumes': {},
                'timeout': 300
            },
            'lightweight_android': {
                'image': 'android-x86:latest',
                'ports': {'5555/tcp': 5555},
                'environment': {'DISPLAY': ':99'},
                'volumes': {},
                'timeout': 180
            }
        }
    
    def initialize_docker(self) -> Dict[str, Any]:
        """Initialize Docker client and check availability"""
        try:
            self.docker_client = docker.from_env()
            
            # Test Docker connection
            self.docker_client.ping()
            
            # Check available images
            images = [img.tags[0] if img.tags else 'untagged' 
                     for img in self.docker_client.images.list()]
            
            return {
                'success': True,
                'docker_available': True,
                'available_images': images[:10],  # Limit output
                'docker_version': self.docker_client.version()['Version']
            }
            
        except Exception as e:
            return {
                'success': False,
                'docker_available': False,
                'error': f'Docker initialization failed: {str(e)}'
            }
    
    def create_sandbox(self, sandbox_type: str = 'lightweight_android') -> Dict[str, Any]:
        """Create isolated sandbox environment"""
        try:
            if not self.docker_client:
                docker_init = self.initialize_docker()
                if not docker_init['success']:
                    return self._create_local_sandbox()
            
            config = self.sandbox_configs.get(sandbox_type, self.sandbox_configs['lightweight_android'])
            
            # Create container
            container = self.docker_client.containers.run(
                image=config['image'],
                ports=config['ports'],
                environment=config['environment'],
                volumes=config['volumes'],
                detach=True,
                remove=True,
                name=f"apk_sandbox_{int(time.time())}"
            )
            
            # Wait for container to start
            time.sleep(10)
            
            container_id = container.id
            self.active_containers[container_id] = {
                'container': container,
                'created_at': datetime.now(),
                'type': sandbox_type
            }
            
            return {
                'success': True,
                'sandbox_id': container_id,
                'sandbox_type': sandbox_type,
                'container_name': container.name,
                'status': 'running'
            }
            
        except Exception as e:
            # Fallback to local sandbox
            return self._create_local_sandbox()
    
    def _create_local_sandbox(self) -> Dict[str, Any]:
        """Create local filesystem-based sandbox as fallback"""
        try:
            sandbox_dir = tempfile.mkdtemp(prefix='apk_local_sandbox_')
            
            # Create sandbox structure
            dirs_to_create = [
                'apps', 'logs', 'data', 'tmp', 'analysis'
            ]
            
            for dir_name in dirs_to_create:
                os.makedirs(os.path.join(sandbox_dir, dir_name), exist_ok=True)
            
            sandbox_id = f"local_{int(time.time())}"
            self.active_containers[sandbox_id] = {
                'type': 'local',
                'path': sandbox_dir,
                'created_at': datetime.now()
            }
            
            return {
                'success': True,
                'sandbox_id': sandbox_id,
                'sandbox_type': 'local_filesystem',
                'sandbox_path': sandbox_dir,
                'status': 'ready'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Local sandbox creation failed: {str(e)}'
            }
    
    def install_apk_in_sandbox(self, sandbox_id: str, apk_path: str) -> Dict[str, Any]:
        """Install APK in specified sandbox"""
        try:
            if sandbox_id not in self.active_containers:
                return {'success': False, 'error': 'Sandbox not found'}
            
            sandbox_info = self.active_containers[sandbox_id]
            
            if sandbox_info['type'] == 'local':
                return self._install_apk_local(sandbox_info, apk_path)
            else:
                return self._install_apk_docker(sandbox_info, apk_path)
                
        except Exception as e:
            return {'success': False, 'error': f'APK installation failed: {str(e)}'}
    
    def _install_apk_local(self, sandbox_info: Dict, apk_path: str) -> Dict[str, Any]:
        """Install APK in local sandbox (simulation)"""
        try:
            sandbox_path = sandbox_info['path']
            
            # Copy APK to sandbox
            apk_name = os.path.basename(apk_path)
            sandbox_apk_path = os.path.join(sandbox_path, 'apps', apk_name)
            shutil.copy2(apk_path, sandbox_apk_path)
            
            # Extract basic info using aapt (if available)
            package_info = self._extract_package_info(apk_path)
            
            # Create installation record
            install_record = {
                'apk_path': sandbox_apk_path,
                'package_name': package_info.get('package_name', 'unknown'),
                'installed_at': datetime.now().isoformat(),
                'status': 'simulated_install'
            }
            
            # Save installation record
            record_path = os.path.join(sandbox_path, 'data', 'install_record.json')
            with open(record_path, 'w') as f:
                json.dump(install_record, f, indent=2)
            
            return {
                'success': True,
                'package_name': install_record['package_name'],
                'install_type': 'simulated',
                'install_record': install_record
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Local APK installation failed: {str(e)}'}
    
    def _install_apk_docker(self, sandbox_info: Dict, apk_path: str) -> Dict[str, Any]:
        """Install APK in Docker container"""
        try:
            container = sandbox_info['container']
            
            # Copy APK to container
            apk_name = os.path.basename(apk_path)
            container_apk_path = f'/tmp/{apk_name}'
            
            with open(apk_path, 'rb') as apk_file:
                container.put_archive('/tmp/', apk_file.read())
            
            # Install APK using ADB
            install_cmd = f'adb install -r {container_apk_path}'
            result = container.exec_run(install_cmd)
            
            if result.exit_code != 0:
                return {
                    'success': False,
                    'error': f'ADB install failed: {result.output.decode()}'
                }
            
            # Extract package name
            package_info = self._extract_package_info(apk_path)
            
            return {
                'success': True,
                'package_name': package_info.get('package_name', 'unknown'),
                'install_type': 'docker_adb',
                'install_output': result.output.decode()
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Docker APK installation failed: {str(e)}'}
    
    def _extract_package_info(self, apk_path: str) -> Dict[str, Any]:
        """Extract basic package information from APK"""
        try:
            # Try using aapt
            result = subprocess.run([
                'aapt', 'dump', 'badging', apk_path
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                package_name = None
                version_name = None
                
                for line in result.stdout.split('\n'):
                    if line.startswith('package:'):
                        import re
                        name_match = re.search(r"name='([^']+)'", line)
                        version_match = re.search(r"versionName='([^']+)'", line)
                        
                        if name_match:
                            package_name = name_match.group(1)
                        if version_match:
                            version_name = version_match.group(1)
                
                return {
                    'package_name': package_name or 'unknown',
                    'version_name': version_name or 'unknown',
                    'extraction_method': 'aapt'
                }
            
        except:
            pass
        
        # Fallback: generate from filename
        apk_name = os.path.basename(apk_path).replace('.apk', '')
        return {
            'package_name': f'com.unknown.{apk_name}',
            'version_name': '1.0',
            'extraction_method': 'filename_fallback'
        }
    
    def execute_in_sandbox(self, sandbox_id: str, command: str) -> Dict[str, Any]:
        """Execute command in sandbox environment"""
        try:
            if sandbox_id not in self.active_containers:
                return {'success': False, 'error': 'Sandbox not found'}
            
            sandbox_info = self.active_containers[sandbox_id]
            
            if sandbox_info['type'] == 'local':
                return self._execute_local_command(sandbox_info, command)
            else:
                return self._execute_docker_command(sandbox_info, command)
                
        except Exception as e:
            return {'success': False, 'error': f'Command execution failed: {str(e)}'}
    
    def _execute_local_command(self, sandbox_info: Dict, command: str) -> Dict[str, Any]:
        """Execute command in local sandbox (limited simulation)"""
        try:
            sandbox_path = sandbox_info['path']
            
            # Simulate command execution
            simulated_commands = {
                'ps': 'Simulated process list',
                'netstat': 'Simulated network connections',
                'ls': f'Contents of {sandbox_path}',
                'logcat': 'Simulated Android logs'
            }
            
            output = simulated_commands.get(command.split()[0], f'Simulated output for: {command}')
            
            # Log command execution
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'command': command,
                'output': output,
                'execution_type': 'simulated'
            }
            
            log_path = os.path.join(sandbox_path, 'logs', 'command_log.json')
            logs = []
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    logs = json.load(f)
            
            logs.append(log_entry)
            
            with open(log_path, 'w') as f:
                json.dump(logs, f, indent=2)
            
            return {
                'success': True,
                'output': output,
                'execution_type': 'simulated',
                'exit_code': 0
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Local command execution failed: {str(e)}'}
    
    def _execute_docker_command(self, sandbox_info: Dict, command: str) -> Dict[str, Any]:
        """Execute command in Docker container"""
        try:
            container = sandbox_info['container']
            
            result = container.exec_run(command)
            
            return {
                'success': result.exit_code == 0,
                'output': result.output.decode(),
                'execution_type': 'docker',
                'exit_code': result.exit_code
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Docker command execution failed: {str(e)}'}
    
    def monitor_sandbox(self, sandbox_id: str, duration: int = 60) -> Dict[str, Any]:
        """Monitor sandbox activity for specified duration"""
        try:
            if sandbox_id not in self.active_containers:
                return {'success': False, 'error': 'Sandbox not found'}
            
            monitoring_data = {
                'start_time': datetime.now().isoformat(),
                'duration': duration,
                'activities': [],
                'resource_usage': [],
                'network_activity': [],
                'file_operations': []
            }
            
            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=self._monitor_sandbox_activity,
                args=(sandbox_id, duration, monitoring_data)
            )
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Wait for monitoring to complete
            monitor_thread.join(timeout=duration + 10)
            
            monitoring_data['end_time'] = datetime.now().isoformat()
            
            return {
                'success': True,
                'monitoring_data': monitoring_data
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Sandbox monitoring failed: {str(e)}'}
    
    def _monitor_sandbox_activity(self, sandbox_id: str, duration: int, monitoring_data: Dict):
        """Monitor sandbox activity in background thread"""
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                # Monitor resource usage
                if sandbox_id in self.active_containers:
                    sandbox_info = self.active_containers[sandbox_id]
                    
                    if sandbox_info['type'] != 'local':
                        # Docker container monitoring
                        container = sandbox_info['container']
                        stats = container.stats(stream=False)
                        
                        monitoring_data['resource_usage'].append({
                            'timestamp': datetime.now().isoformat(),
                            'cpu_usage': self._calculate_cpu_usage(stats),
                            'memory_usage': stats['memory_stats'].get('usage', 0),
                            'network_rx': stats['networks']['eth0']['rx_bytes'] if 'networks' in stats else 0
                        })
                    else:
                        # Local sandbox monitoring (simulated)
                        monitoring_data['activities'].append({
                            'timestamp': datetime.now().isoformat(),
                            'activity': 'simulated_monitoring',
                            'details': 'Local sandbox activity simulation'
                        })
                
                time.sleep(5)  # Monitor every 5 seconds
                
            except Exception as e:
                monitoring_data['activities'].append({
                    'timestamp': datetime.now().isoformat(),
                    'activity': 'monitoring_error',
                    'error': str(e)
                })
    
    def _calculate_cpu_usage(self, stats: Dict) -> float:
        """Calculate CPU usage percentage from Docker stats"""
        try:
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                       stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                          stats['precpu_stats']['system_cpu_usage']
            
            if system_delta > 0:
                return (cpu_delta / system_delta) * 100.0
            return 0.0
            
        except:
            return 0.0
    
    def cleanup_sandbox(self, sandbox_id: str) -> Dict[str, Any]:
        """Clean up and remove sandbox environment"""
        try:
            if sandbox_id not in self.active_containers:
                return {'success': False, 'error': 'Sandbox not found'}
            
            sandbox_info = self.active_containers[sandbox_id]
            
            if sandbox_info['type'] == 'local':
                # Clean up local sandbox
                sandbox_path = sandbox_info['path']
                if os.path.exists(sandbox_path):
                    shutil.rmtree(sandbox_path)
            else:
                # Stop and remove Docker container
                container = sandbox_info['container']
                container.stop()
                container.remove()
            
            # Remove from active containers
            del self.active_containers[sandbox_id]
            
            return {
                'success': True,
                'sandbox_id': sandbox_id,
                'cleanup_type': sandbox_info['type']
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Sandbox cleanup failed: {str(e)}'}
    
    def list_active_sandboxes(self) -> Dict[str, Any]:
        """List all active sandbox environments"""
        sandboxes = []
        
        for sandbox_id, info in self.active_containers.items():
            sandbox_data = {
                'sandbox_id': sandbox_id,
                'type': info['type'],
                'created_at': info['created_at'].isoformat(),
                'age_seconds': (datetime.now() - info['created_at']).total_seconds()
            }
            
            if info['type'] != 'local':
                try:
                    container = info['container']
                    sandbox_data['status'] = container.status
                    sandbox_data['container_name'] = container.name
                except:
                    sandbox_data['status'] = 'unknown'
            else:
                sandbox_data['path'] = info['path']
                sandbox_data['status'] = 'active'
            
            sandboxes.append(sandbox_data)
        
        return {
            'active_sandboxes': len(sandboxes),
            'sandboxes': sandboxes
        }

if __name__ == '__main__':
    # Example usage
    manager = SandboxManager()
    
    # Initialize and test
    docker_status = manager.initialize_docker()
    print(f"Docker status: {docker_status}")
    
    # Create sandbox
    sandbox = manager.create_sandbox()
    print(f"Sandbox created: {sandbox}")
