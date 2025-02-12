from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import Q
from .models import User, Document
from django.db import IntegrityError
from django.contrib import messages
from django.contrib.auth.hashers import check_password, make_password


def home(request):
    return render(request, 'index.html')


def base(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must log in first!")
        return redirect('login')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found. Please log in again.")
        return redirect('login')

    return render(request, 'base.html', {"user": user})


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
        except User.DoesNotExist:
            messages.error(request, "User does not exist.")
    return render(request, 'login.html')


def send_document(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must log in first!")
        return redirect('login')

    sender = User.objects.get(id=user_id)
    users = User.objects.exclude(id=user_id)

    if request.method == 'POST':
        doc_name = request.POST['doc_name']
        receiver_id = request.POST['receiver']
        description = request.POST['description']
        is_urgent = request.POST.get('is_urgent', False)
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
            messages.success(request, f"Document '{doc_name}' sent to {receiver.username} successfully!")
            return redirect('track_documents')
        except User.DoesNotExist:
            messages.error(request, "Selected user does not exist.")
    return render(request, 'send_document.html', {"users": users})


def track_documents(request):
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must log in first!")
        return redirect('login')

    user = User.objects.get(id=user_id)
    query = request.GET.get('q', '')

    received_documents = Document.objects.filter(receiver=user)
    sent_documents = Document.objects.filter(sender=user)

    if query:
        received_documents = received_documents.filter(
            Q(doc_name__icontains=query) | Q(sender__username__icontains=query)
        )
        sent_documents = sent_documents.filter(
            Q(doc_name__icontains=query) | Q(receiver__username__icontains=query)
        )

    return render(request, 'truck_document.html', {
        "received_documents": received_documents,
        "sent_documents": sent_documents
    })


def document_detail(request, document_id):
    """
    When a document is viewed by its receiver, mark it as received and read.
    """
    user_id = request.session.get('user_id')
    if not user_id:
        messages.error(request, "You must log in first!")
        return redirect('login')

    document = get_object_or_404(Document, pk=document_id)

    # If the logged-in user is the receiver, mark the document as received and read.
    if request.session.get('user_id') == document.receiver.id:
        if not document.is_received:
            document.is_received = True
        if not document.is_read:
            document.is_read = True
        document.save()

    return render(request, 'document_detail.html', {'document': document})


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
