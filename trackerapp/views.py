from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import Q
from .models import User, Document
from django.db import IntegrityError
from django.contrib import messages
from django.contrib.auth.hashers import check_password, make_password
from django.http import FileResponse, Http404
import os

# Import these for sending notifications
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

# Helper function to get document statistics for a given user
def get_document_counts(user):
    new_documents = Document.objects.filter(receiver=user, is_received=False).count()
    processed_documents = Document.objects.filter(receiver=user, is_read=True).count()
    # Updated pending_documents: any document that has not been read is considered pending.
    pending_documents = Document.objects.filter(receiver=user, is_read=False).count()
    # If your Document model has an 'is_rejected' field, this will work dynamically;
    # otherwise, it will default to 0.
    rejected_documents = Document.objects.filter(receiver=user, is_rejected=True).count() if hasattr(Document, 'is_rejected') else 0
    return {
        "new_documents": new_documents,
        "processed_documents": processed_documents,
        "pending_documents": pending_documents,
        "rejected_documents": rejected_documents,
    }

def home(request):
    return render(request, 'index.html')

def base(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must log in first!")
        return redirect('login')
    try:
        user = User.objects.get(id=user_id)
        counts = get_document_counts(user)
        context = {
            "user": user,
            **counts
        }
        return render(request, 'base.html', context)
    except User.DoesNotExist:
        messages.error(request, "User not found. Please log in again.")
        return redirect('login')

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        try:
            user = User.objects.get(email=email)
            if check_password(password, user.password):
                request.session['user_id'] = user.id
                request.session['username'] = user.username
                request.session.modified = True
                messages.success(request, "Login successful!")
                return redirect('base')
            else:
                messages.error(request, "Invalid email or password.")
                return redirect('login')
        except User.DoesNotExist:
            messages.error(request, "Invalid email or password.")
            return redirect('login')
    return render(request, 'login.html')

def send_document(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must log in first!")
        return redirect('login')

    user = User.objects.get(id=user_id)
    counts = get_document_counts(user)

    sender = user
    users = User.objects.exclude(id=user_id)
    if request.method == 'POST':
        doc_name = request.POST['doc_name']
        receiver_id = request.POST['receiver']
        description = request.POST['description']
        is_urgent = request.POST.get('is_urgent', False)
        # Note: Ensure the file input name in your HTML form matches this key ("file")
        file = request.FILES.get('file', None)
        try:
            receiver = User.objects.get(id=receiver_id)
            document = Document(
                sender=sender,
                receiver=receiver,
                doc_name=doc_name,
                description=description,
                is_urgent=bool(is_urgent),
                file=file
            )
            # Mark the document as sent when it is created.
            document.is_sent = True
            document.save()

            # Send a notification after the document is created.
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                "notifications",  # Group name that your consumer is listening on
                {
                    "type": "send_notification",  # This maps to a method in your WebSocket consumer
                    "message": f"New document '{document.doc_name}' sent from {sender.username}.",
                }
            )

            # Raise an urgent alert if applicable.
            if document.is_urgent:
                messages.warning(request, "Alert: This document is marked as urgent and requires immediate attention!")

            messages.success(request, f"Document '{doc_name}' sent to {receiver.username} successfully!")
            return redirect('track_documents')
        except User.DoesNotExist:
            messages.error(request, "Selected user does not exist.")

    context = {
        "users": users,
        **counts
    }
    return render(request, 'send_document.html', context)

def track_documents(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must log in first!")
        return redirect('login')

    user = User.objects.get(id=user_id)
    counts = get_document_counts(user)
    query = request.GET.get('q', '')
    filter_type = request.GET.get('filter', '')

    # Base queries
    received_documents = Document.objects.filter(receiver=user)
    sent_documents = Document.objects.filter(sender=user)

    # Apply text search if query exists
    if query:
        received_documents = received_documents.filter(
            Q(doc_name__icontains=query) | Q(sender__username__icontains=query)
        )
        sent_documents = sent_documents.filter(
            Q(doc_name__icontains=query) | Q(receiver__username__icontains=query)
        )

    # Apply status filters if requested
    if filter_type == 'new':
        received_documents = received_documents.filter(is_received=False)
    elif filter_type == 'processed':
        received_documents = received_documents.filter(is_read=True)
    elif filter_type == 'pending':
        # Updated: Any document that has not been read is considered pending.
        received_documents = received_documents.filter(is_read=False)
    elif filter_type == 'rejected':
        # Implement this if you add a rejected status field
        pass

    context = {
        "received_documents": received_documents,
        "sent_documents": sent_documents,
        "filter_type": filter_type,
        **counts
    }
    return render(request, 'truck_document.html', context)

def document_detail(request, document_id):
    """
    When a document is viewed by its receiver, mark it as received and read.
    Also, if the document is urgent, an alert is raised.
    Additionally, if a download is requested via the query string,
    the document file will be served for download.
    """
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must log in first!")
        return redirect('login')

    user = User.objects.get(id=user_id)
    document = get_object_or_404(Document, pk=document_id)
    counts = get_document_counts(user)

    # Ensure the user is authorized (either sender or receiver)
    if user_id != document.receiver.id and user_id != document.sender.id:
        messages.error(request, "You do not have permission to view this document.")
        return redirect('track_documents')

    # Handle file download request if the 'download' parameter is present
    if 'download' in request.GET:
        if not document.file:
            raise Http404("File not found.")
        response = FileResponse(document.file.open(), as_attachment=True)
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(document.file.name)}"'
        return response

    # If the receiver views the document, mark it as received and read.
    if user_id == document.receiver.id:
        if not document.is_received:
            document.is_received = True
        if not document.is_read:
            document.is_read = True
        document.save()

    # Raise an alert if the document is marked as urgent.
    if document.is_urgent:
        messages.warning(request, "Alert: This document is marked as urgent. Please prioritize your action!")

    context = {
        'document': document,
        **counts
    }
    return render(request, 'document_detail.html', context)

def register(request):
    if request.method == 'POST':
        username = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm-password']
        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return render(request, 'register.html')
        try:
            hashed_password = make_password(password)
            user = User(username=username, email=email, password=hashed_password)
            user.save()
            messages.success(request, "Registration successful! You can now log in.")
            return redirect('login')
        except IntegrityError:
            messages.error(request, "Username or email already exists. Please try another.")
            return render(request, 'register.html')
    return render(request, 'register.html')

def support(request):
    return render(request, 'support.html')

def statistics(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must log in first!")
        return redirect('login')
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found. Please log in again.")
        return redirect('login')
    counts = get_document_counts(user)
    total_received = Document.objects.filter(receiver=user).count()
    total_sent = Document.objects.filter(sender=user).count()
    total_documents = total_received + total_sent

    context = {
        "user": user,
        **counts,
        "total_received": total_received,
        "total_sent": total_sent,
        "total_documents": total_documents,
    }
    return render(request, 'statistics.html', context)

def account_settings(request):
    # Check if user is logged in via session
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must log in first!")
        return redirect('login')
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found. Please log in again.")
        return redirect('login')

    if request.method == 'POST':
        # Get the form data
        username = request.POST.get('username')
        email = request.POST.get('email')
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_new_password = request.POST.get('confirm_new_password')

        updated = False

        # Update username if it has changed
        if username and username != user.username:
            user.username = username
            updated = True

        # Update email if it has changed
        if email and email != user.email:
            user.email = email
            updated = True

        # Process password change if any of the password fields are filled
        if current_password or new_password or confirm_new_password:
            # All three fields must be provided
            if not (current_password and new_password and confirm_new_password):
                messages.error(request, "Please fill out all password fields to change your password.")
                return render(request, 'account_settings.html', {'user': user})
            # Verify the current password is correct
            if not check_password(current_password, user.password):
                messages.error(request, "Current password is incorrect.")
                return render(request, 'account_settings.html', {'user': user})
            # Check that new password fields match
            if new_password != confirm_new_password:
                messages.error(request, "New passwords do not match.")
                return render(request, 'account_settings.html', {'user': user})
            # Update the password
            user.password = make_password(new_password)
            updated = True

        if updated:
            user.save()
            messages.success(request, "Account settings updated successfully.")
        else:
            messages.info(request, "No changes made.")
        return redirect('settings')

    # For GET requests, simply render the account settings template with the current user data
    return render(request, 'account_settings.html', {'user': user})
