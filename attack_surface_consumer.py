import json
import time
from rabbitmq_handler import RabbitMQHandler
import subprocess
import os

class AttackSurfaceConsumer:
    def __init__(self, rabbitmq_config: dict, project_id: int):
        """
        Initialize the attack surface consumer
        
        Args:
            rabbitmq_config: Dictionary containing RabbitMQ connection details
            project_id: The project ID to use for processing
        """
        self.rabbitmq = RabbitMQHandler(
            host=rabbitmq_config.get('host', 'localhost'),
            port=rabbitmq_config.get('port', 5672),
            username=rabbitmq_config.get('username', 'guest'),
            password=rabbitmq_config.get('password', 'guest'),
            queue_name=rabbitmq_config.get('queue_name', 'attack_surface_queue')
        )
        self.project_id = project_id
        self.script_dir = os.path.dirname(os.path.abspath(__file__))

    def process_target(self, message: dict) -> bool:
        """
        Process a target from the queue
        
        Args:
            message: The message containing the target information
            
        Returns:
            bool: True if processing was successful, False otherwise
        """
        try:
            print(f"\n{'='*80}")
            print("PROCESSING NEW TARGET")
            print(f"{'='*80}")
            
            # Extract target information
            target = message.get('target')
            if not target:
                print("No target found in message")
                return False
                
            print(f"Target: {target}")
            
            # Run the attack surface script
            try:
                # Construct the command
                script_path = os.path.join(self.script_dir, 'send_attack_surface.py')
                command = ['python', script_path, str(self.project_id), target]
                
                print(f"Running command: {' '.join(command)}")
                
                # Run the script
                result = subprocess.run(
                    command,
                    check=True,
                    capture_output=True,
                    text=True
                )
                
                print("\nScript Output:")
                print(result.stdout)
                
                if result.stderr:
                    print("\nScript Errors:")
                    print(result.stderr)
                
                print(f"\nScript completed with return code: {result.returncode}")
                return result.returncode == 0
                
            except subprocess.CalledProcessError as e:
                print(f"Error running attack surface script: {str(e)}")
                print(f"Return code: {e.returncode}")
                print(f"Output: {e.output}")
                return False
                
        except Exception as e:
            print(f"Error processing target: {str(e)}")
            return False

    def start_consuming(self):
        """Start consuming messages from the queue"""
        if self.rabbitmq.connect():
            print(f"Starting to consume messages for project {self.project_id}")
            self.rabbitmq.receive_message(callback=self.process_target)
        else:
            print("Failed to connect to RabbitMQ")

    def close(self):
        """Close the RabbitMQ connection"""
        self.rabbitmq.close()

def main():
    # RabbitMQ configuration
    rabbitmq_config = {
        'host': 'b-0f40a51e-e83b-45db-972b-e65337fbbfba.mq.us-west-2.on.aws',
        'port': 5671,  # SSL/TLS port for AWS MQ
        'username': 'RangerMQUser',
        'password': '4382gfrwb#$@#RWFVFDVBVSD',
        'queue_name': 'attack_surface_queue'
    }
    
    # Project ID
    project_id = 1  # Replace with your project ID
    
    # Create consumer
    consumer = AttackSurfaceConsumer(rabbitmq_config, project_id)
    
    try:
        # Start consuming messages
        consumer.start_consuming()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        consumer.close()

if __name__ == "__main__":
    main() 