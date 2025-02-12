from django.db import models


class User(models.Model):
    username = models.CharField(max_length=100, unique=True, default='default_username')
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)

    def __str__(self):
        return self.username


class Document(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_documents')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_documents')
    doc_name = models.CharField(max_length=255)
    file = models.FileField(upload_to='documents/', blank=True, null=True)  # File is optional
    description = models.TextField()
    is_urgent = models.BooleanField(default=False)  # Urgent flag
    timestamp = models.DateTimeField(auto_now_add=True)

    # New fields for tracking document status:
    is_sent = models.BooleanField(default=False)  # Mark as True when the document is sent.
    is_received = models.BooleanField(default=False)  # Mark as True when the receiver acknowledges receipt.
    is_read = models.BooleanField(default=False)  # Track if the receiver has read the document.

    def __str__(self):
        return f"{self.doc_name} from {self.sender.username} to {self.receiver.username}"
