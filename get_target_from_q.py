from rabbitmq_handler import RabbitMQHandler

def process_message(message):
    print(f"Received message: {message}")
    # Return True if processing was successful
    return True

# Use the same credentials and host as in your consumer
rabbitmq = RabbitMQHandler(
    host='b-0f40a51e-e83b-45db-972b-e65337fbbfba.mq.us-west-2.on.aws',
    port=5671,
    username='RangerMQUser',
    password='4382gfrwb#$@#RWFVFDVBVSD',
    queue_name='attack_surface_queue'
)

if rabbitmq.connect():
    rabbitmq.receive_message(callback=process_message)
    rabbitmq.close()
    print("Test message received!")
else:
    print("Failed to connect to RabbitMQ.") 