from channels.generic.websocket import AsyncWebsocketConsumer
import json

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Join the "notifications" group
        await self.channel_layer.group_add("notifications", self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        # Leave the "notifications" group on disconnect
        await self.channel_layer.group_discard("notifications", self.channel_name)

    async def send_notification(self, event):
        # Receive the notification and send it to the WebSocket
        message = event.get("message", "")
        await self.send(text_data=json.dumps({"message": message}))
