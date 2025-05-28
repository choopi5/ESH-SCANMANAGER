from rabbitmq_handler import RabbitMQHandler

# Use the same credentials and host as in your consumer
rabbitmq = RabbitMQHandler(
    host='b-0f40a51e-e83b-45db-972b-e65337fbbfba.mq.us-west-2.on.aws',
    port=5671,
    username='RangerMQUser',
    password='4382gfrwb#$@#RWFVFDVBVSD',
    queue_name='attack_surface_queue'
)

# Example message (must match what your consumer expects)
message = {
    "target": "1.com",
    "target": "2.com"
}

if rabbitmq.connect():
    rabbitmq.send_message(message)
    rabbitmq.close()
    print("Test message sent!")
else:
    print("Failed to connect to RabbitMQ.") 