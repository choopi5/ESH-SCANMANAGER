import pika
import json
import time
from typing import Optional, Callable
import ssl

class RabbitMQHandler:
    def __init__(self, host: str = 'localhost', port: int = 5672, 
                 username: str = 'RangerMQUser', password: str = '4382gfrwb#$@#RWFVFDVBVSD',
                 queue_name: str = 'attack_surface_queue'):
        """
        Initialize RabbitMQ connection parameters
        
        Args:
            host: RabbitMQ server host
            port: RabbitMQ server port
            username: RabbitMQ username
            password: RabbitMQ password
            queue_name: Name of the queue to use
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.queue_name = queue_name
        self.connection = None
        self.channel = None

    def connect(self) -> bool:
        """
        Establish connection to RabbitMQ server with SSL/TLS support for AWS MQ
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            credentials = pika.PlainCredentials(self.username, self.password)
            context = ssl.create_default_context()
            parameters = pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                credentials=credentials,
                ssl_options=pika.SSLOptions(context),
                heartbeat=600,
                blocked_connection_timeout=300
            )
            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()
            self.channel.queue_declare(queue=self.queue_name, durable=True)
            print(f"Successfully connected to RabbitMQ at {self.host}:{self.port} (SSL enabled)")
            return True
        except Exception as e:
            print(f"Failed to connect to RabbitMQ: {str(e)}")
            return False

    def send_message(self, message: dict) -> bool:
        """
        Send a message to the queue
        
        Args:
            message: Dictionary containing the message to send
            
        Returns:
            bool: True if message sent successfully, False otherwise
        """
        try:
            if not self.connection or self.connection.is_closed:
                if not self.connect():
                    return False

            # Convert message to JSON string
            message_body = json.dumps(message)
            
            # Publish message
            self.channel.basic_publish(
                exchange='',
                routing_key=self.queue_name,
                body=message_body,
                properties=pika.BasicProperties(
                    delivery_mode=2,  # make message persistent
                    content_type='application/json'
                )
            )
            print(f"Message sent to queue {self.queue_name}")
            return True
            
        except Exception as e:
            print(f"Failed to send message: {str(e)}")
            return False

    def receive_message(self, callback: Optional[Callable] = None) -> Optional[dict]:
        """
        Receive a message from the queue and process it. The message will only be acknowledged
        after the callback function completes successfully.
        
        Args:
            callback: Function to process the message. Must return True if processing was successful,
                    False otherwise. If False, the message will be requeued.
            
        Returns:
            dict: The received message if no callback provided, None otherwise
        """
        try:
            if not self.connection or self.connection.is_closed:
                if not self.connect():
                    return None

            # Define message processing function
            def process_message(ch, method, properties, body):
                try:
                    message = json.loads(body)
                    print(f"Received message: {message}")
                    
                    if callback:
                        try:
                            # Process the message
                            success = callback(message)
                            
                            if success:
                                # Acknowledge the message only if processing was successful
                                ch.basic_ack(delivery_tag=method.delivery_tag)
                                print(f"Message processed successfully and acknowledged")
                            else:
                                # Reject the message and requeue it
                                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
                                print(f"Message processing failed, requeuing message")
                        except Exception as e:
                            # If callback raises an exception, reject and requeue the message
                            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
                            print(f"Error processing message: {str(e)}")
                            print("Message requeued")
                    else:
                        # If no callback provided, just acknowledge the message
                        ch.basic_ack(delivery_tag=method.delivery_tag)
                        print("No callback provided, message acknowledged")
                        
                except json.JSONDecodeError:
                    # If message can't be decoded, reject it without requeuing
                    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                    print(f"Failed to decode message: {body}")
                    print("Message rejected (not requeued)")

            # Set prefetch count to 1 to ensure we only get one message at a time
            self.channel.basic_qos(prefetch_count=1)
            
            # Start consuming messages
            self.channel.basic_consume(
                queue=self.queue_name,
                on_message_callback=process_message
            )
            
            print(f"Waiting for messages on queue {self.queue_name}")
            self.channel.start_consuming()
            
        except Exception as e:
            print(f"Failed to receive message: {str(e)}")
            return None

    def close(self):
        """Close the RabbitMQ connection"""
        try:
            if self.connection and not self.connection.is_closed:
                self.connection.close()
                print("RabbitMQ connection closed")
        except Exception as e:
            print(f"Error closing connection: {str(e)}")

# Example usage
if __name__ == "__main__":
    # Create RabbitMQ handler instance
    rabbitmq = RabbitMQHandler(
        host='localhost',  # Replace with your RabbitMQ server host
        port=5672,         # Replace with your RabbitMQ server port
        username='guest',  # Replace with your RabbitMQ username
        password='guest',  # Replace with your RabbitMQ password
        queue_name='attack_surface_queue'
    )

    # Example of sending a message
    message = {
        "type": "attack_surface",
        "data": {
            "domain": "example.com",
            "status": "alive"
        }
    }
    
    if rabbitmq.connect():
        # Send message
        rabbitmq.send_message(message)
        
        # Example callback function that returns True on success, False on failure
        def process_message(message):
            try:
                print(f"Processing message: {message}")
                # Add your message processing logic here
                
                # Simulate some processing
                time.sleep(2)
                
                # Return True if processing was successful
                return True
            except Exception as e:
                print(f"Error in message processing: {str(e)}")
                return False
        
        # Receive messages
        rabbitmq.receive_message(callback=process_message)
        
        # Close connection when done
        rabbitmq.close() 