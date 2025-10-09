# -*- coding: utf-8 -*-
from distutils.version import LooseVersion
from rest_framework import status, generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from datetime import datetime, timedelta
import random
import string
from collections import defaultdict
import pytz
# from . import serializers
from .serializers import PurgeSerializer,ReleaseHistorySerializer,ReleaseSerializer,UpdateCheckSerializer
from .models import *
from django.shortcuts import render,redirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth.decorators import login_required
from django.utils.dateparse import parse_date
from django.views.decorators.cache import never_cache
from django.core.serializers import serialize
from django.utils.timezone import now
from django.db.models import Q
from django.core.urlresolvers import reverse
from functools import wraps
import logging
from django.db.models import Count, F
import json
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
import uuid
import urllib
from django.http import HttpResponse, HttpResponseRedirect
from django.conf import settings
import adal
import jwt
import requests
from django.contrib.auth import get_user_model

# utils/pagination.py

from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.db.models import Count, Max, Q
from django.utils.timezone import now
logger = logging.getLogger('scheduler')

def no_cache_response(response):
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response

def session_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_authenticated'):
            logger.info("Session required: Redirecting to login")
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

class SmartPaginator:
    def __init__(self, queryset, page, per_page):
        self.paginator = Paginator(queryset, per_page)
        self.page_number = self._safe_int(page, 1)
        self.page_obj = self._get_page()
        self.total_items = self.paginator.count
        self.start_item, self.end_item = self._calculate_item_range()
        self.page_range = self._smart_page_range()

    def _safe_int(self, value, default):
        try:
            return int(value)
        except (ValueError, TypeError):
            return default

    def _get_page(self):
        try:
            return self.paginator.page(self.page_number)
        except (PageNotAnInteger, EmptyPage):
            return self.paginator.page(1)

    def _calculate_item_range(self):
        if self.total_items == 0:
            return 0, 0
        start = (self.page_obj.number - 1) * self.paginator.per_page + 1
        end = min(start + self.paginator.per_page - 1, self.total_items)
        return start, end

    def _smart_page_range(self):
        total = self.paginator.num_pages
        current = self.page_obj.number
        range_list = []

        if total <= 7:
            return list(range(1, total + 1))

        range_list.append(1)
        if current <= 4:
            range_list.extend(range(2, min(total, 6) + 1))
            if total > 6:
                range_list.append("...")
        elif current >= total - 3:
            if total > 6:
                range_list.append("...")
            range_list.extend(range(max(2, total - 4), total + 1))
        else:
            range_list.append("...")
            range_list.extend(range(current - 1, current + 2))
            range_list.append("...")
            range_list.append(total)

        return range_list

def custom_404(request):
    return render(request, '404.html',{}, status=404)

def build_auth_url():
    state = str(uuid.uuid4())
    request.session['auth_state'] = state
    return (
        "%s/oauth2/authorize?client_id=%s&response_type=code&redirect_uri=%s&state=%s&resource=%s"
        % (
            settings.AZURE_AD['AUTHORITY'],
            settings.AZURE_AD['CLIENT_ID'],
            urllib.quote(settings.AZURE_AD['REDIRECT_URI']),
            state,
            urllib.quote(settings.AZURE_AD['RESOURCE'])
        )
    )

def login_view(request):
    logger.info("login view")

    # If user is already authenticated, redirect to the dashboard
    if request.user.is_authenticated():
        response = redirect('dashboard')
        return no_cache_response(response)

    # Generate state parameter and store in session to prevent CSRF
    state = str(uuid.uuid4())
    request.session['auth_state'] = state

    # Build Azure AD authorization URL
    auth_url = (
        "%s/oauth2/authorize?client_id=%s&response_type=code&redirect_uri=%s&state=%s&resource=%s"
        % (
            settings.AZURE_AD['AUTHORITY'],
            settings.AZURE_AD['CLIENT_ID'],
            urllib.quote(settings.AZURE_AD['REDIRECT_URI']),
            state,
            urllib.quote(settings.AZURE_AD['RESOURCE'])
        )
    )

    return render(request, 'index.html', {'auth_url': auth_url})

def callback(request):
    """Callback endpoint for Azure AD OAuth flow"""

    error = request.GET.get('error')
    if error:
        logger.error("Authentication failed: %s", error)
        return HttpResponse("Authentication failed: %s" % error)

    state = request.GET.get('state')
    if state != request.session.get('auth_state'):
        logger.error("Invalid state parameter. Possible CSRF attack.")
        return HttpResponse("Invalid state parameter. Possible CSRF attack.")

    code = request.GET.get('code')
    if not code:
        logger.error("No authorization code received")
        return HttpResponse("No authorization code received")

    # Exchange code for token
    token_url = "%s/oauth2/token" % settings.AZURE_AD['AUTHORITY']
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': settings.AZURE_AD['CLIENT_ID'],
        'client_secret': settings.AZURE_AD['CLIENT_SECRET'],
        'redirect_uri': settings.AZURE_AD['REDIRECT_URI'],
        'resource': settings.AZURE_AD['RESOURCE']
    }

    token_response = requests.post(token_url, data=payload)
    if token_response.status_code != 200:
        logger.error("Failed to get token from Azure AD")
        return HttpResponse("Failed to get token from Azure AD")

    token_data = token_response.json()
    id_token = token_data.get('id_token')

    if not id_token:
        logger.error("No ID token received")
        return HttpResponse("No ID token received")

    try:
        decoded_token = jwt.decode(id_token, verify=False)  # Disable verification for simplicity
        print("Decoded Token:", decoded_token)
        email = (
            decoded_token.get('upn') or
            decoded_token.get('unique_name')
        )

        if not email:
            logger.error("Email not found in token")
            return HttpResponse("Email not found in token")

        User = get_user_model()
        try:
            user = User.objects.get(email=email)
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, user)
            request.session['user_authenticated'] = True
            if 'auth_state' in request.session:
                del request.session['auth_state']
            logger.info("Redirecting to dashboard for user: %s", user.username)
            return no_cache_response(redirect('dashboard'))
        except User.DoesNotExist:
            logger.warning("User with email %s not found", email)
            request.session['no_access_email'] = email
            return redirect('no_access_view')

    except Exception as e:
        logger.exception("Failed to decode token: %s", str(e))
        return HttpResponse("Failed to decode token")
        
@never_cache
def logout_view(request):
    if 'user_authenticated' in request.session:
        del request.session['user_authenticated']
    logout(request)
    logger.info("Django logout successful")
    response = HttpResponseRedirect(settings.LOGOUT_REDIRECT_URL)
    logger.info("Redirecting to Logout url: %s", settings.LOGOUT_REDIRECT_URL)
    return response
    
#@session_required
def dashboard(request):
    logger.info("dashboard view")
    return render(request,'dash.html')

@never_cache
#@session_required
def customrelease_view(request):
    logger.info("Custom release view")
    return render(request,'customreleaseinfo.html')

@never_cache
def no_access_view(request):
    logger.info("No access view")
    email = request.session.pop('no_access_email', None) 
    context = {
        'email': email
    }   
    return render(request, 'no_access.html', context)

@never_cache
#@session_required
def dashboard_table(request):
    search_query = request.GET.get('search', '')
    sort_by = request.GET.get('sort', 'group')
    
    if search_query:
        releases = Releases.objects.filter(
            Q(release_name__icontains=search_query) | 
            Q(group__icontains=search_query)
        )
    else:
        releases = Releases.objects.all()
    
    groups = {}
    
    for release in releases:
        group_name = release.group
        if group_name not in groups:
            groups[group_name] = {
                'group': group_name,
                'latest_release': None,
                'previous_release': None,
                'release_date': None
            }
    
    for group_name in groups:
        latest_enabled = releases.filter(group=group_name, enabled=True).order_by('-release_date').first()
        if latest_enabled:
            groups[group_name]['latest_release'] = latest_enabled.release_name
            groups[group_name]['release_date'] = latest_enabled.release_date
            
            previous_release = releases.filter(
                group=group_name, 
                enabled=False,
                release_date__lt=latest_enabled.release_date
            ).order_by('-release_date').first()
            
            if previous_release:
                groups[group_name]['previous_release'] = previous_release.release_name
    
    result_data = groups.values()
    
    if sort_by == '-group':
        result_data = sorted(result_data, key=lambda x: x['group'], reverse=True)
    elif sort_by == 'group':
        result_data = sorted(result_data, key=lambda x: x['group'])
    elif sort_by == '-release_date':
        result_data = sorted(result_data, key=lambda x: x['release_date'] if x['release_date'] else None, reverse=True)
    elif sort_by == 'release_date':
        result_data = sorted(result_data, key=lambda x: x['release_date'] if x['release_date'] else None)
    elif sort_by == '-latest_release':
        result_data = sorted(result_data, key=lambda x: x['latest_release'] if x['latest_release'] else '', reverse=True)
    elif sort_by == 'latest_release':
        result_data = sorted(result_data, key=lambda x: x['latest_release'] if x['latest_release'] else '')
    elif sort_by == '-previous_release':
        result_data = sorted(result_data, key=lambda x: x['previous_release'] if x['previous_release'] else '', reverse=True)
    elif sort_by == 'previous_release':
        result_data = sorted(result_data, key=lambda x: x['previous_release'] if x['previous_release'] else '')
    
    context = {
        'releases': result_data,
        'search_query': search_query,
        'current_sort': sort_by
    }
    return render(request, 'dashinfo.html', context)

@never_cache   
#@session_required
def releases_table(request):
    releases = ReleaseHistory.objects.all()

    search_query = request.GET.get('search', '')
    if search_query:
        releases = releases.filter(
            Q(release_name__icontains=search_query) |
            Q(checksum__icontains=search_query) |
            Q(commit_no__icontains=search_query) |
            Q(remarks__icontains=search_query)
        )

    sort = request.GET.get('sort', '-release_date')
    if sort.lstrip('-') not in ['release_name', 'release_date', 'checksum', 'commit_no']:
        sort = '-release_date'
    releases = releases.order_by(sort)

    rows_per_page = request.GET.get('rows', 20)
    page = request.GET.get('page', 1)
    paginated = SmartPaginator(releases, page, rows_per_page)

    context = {
        'releases': paginated.page_obj,
        'search_query': search_query,
        'current_sort': sort,
        'rows_per_page': paginated.paginator.per_page,
        'total_items': paginated.total_items,
        'start_item': paginated.start_item,
        'end_item': paginated.end_item,
        'page_range': paginated.page_range,
    }

    return render(request, 'releaseinfo.html', context)

#@session_required
def update_queue_table(request):
    updates = UpdateQ.objects.all()

    search_query = request.GET.get('search', '')
    if search_query:
        updates = updates.filter(
            Q(portal_name__icontains=search_query)
        )

    sort = request.GET.get('sort', '-request_time')
    if sort.lstrip('-') not in ['portal_name', 'slot', 'request_time']:
        sort = '-request_time'
    updates = updates.order_by(sort)

    rows_per_page = request.GET.get('rows', 10)
    page = request.GET.get('page', 1)
    paginated = SmartPaginator(updates, page, rows_per_page)

    context = {
        'updates': paginated.page_obj,
        'search_query': search_query,
        'current_sort': sort,
        'rows_per_page': paginated.paginator.per_page,
        'total_items': paginated.total_items,
        'start_item': paginated.start_item,
        'end_item': paginated.end_item,
        'page_range': paginated.page_range,
    }
    return render(request, 'queueinfo.html', context)

#@session_required
def get_releasable_versions(request):
    group = request.GET.get('group', '')
    
    if not group:
        return HttpResponse("Group not specified")
    
    releasable_versions = ReleaseHistory.objects.filter(releasable=True).order_by('-release_date')

    try:
        current_release = Releases.objects.get(group=group, enabled=True)
        current_version = current_release.release_name
    except Releases.DoesNotExist:
        current_version = None
    
    context = {
        'releasable_versions': releasable_versions,
        'group': group,
        'current_version': current_version,
    }
    
    return render(request, 'release_edit_form.html', context)

#@session_required
def update_release(request):
    
    group = request.POST.get('group')
    new_release_name = request.POST.get('release_name')
    if not group or not new_release_name:
        logger.error("Group or Release name missing")
        return HttpResponse("Group or Release name missing", status=400)        

    # Disable currently enabled release for the group
    Releases.objects.filter(group=group, enabled=True).update(enabled=False)

    try:
        release = Releases.objects.get(group=group, release_name=new_release_name)
        release.release_date = now()
        release.enabled = True
        release.save()
    except Releases.DoesNotExist:
        Releases.objects.create(
            group=group,
            release_name=new_release_name,
            release_date=now(),
            enabled=True
        )
    logger.info("Group {} updated with release name {}".format(group,new_release_name))
    response = HttpResponse(status=200)
    response['HX-Redirect'] = reverse('dashboard')
    return response

#@session_required
def global_search(request):
    query = request.GET.get('query', '').strip()

    if not query:
        return render(request, 'global_search_results.html', {
            'releases': [],
            'release_histories': [],
            'update_qs': [],
            'portals': [],
            'query': query,
        })

    releases = Releases.objects.filter(
        Q(release_name__icontains=query) |
        Q(group__icontains=query)
    )[:10]

    release_histories = ReleaseHistory.objects.filter(
        Q(release_name__icontains=query) |
        Q(checksum__icontains=query) |
        Q(commit_no__icontains=query) |
        Q(remarks__icontains=query)
    )[:10]

    update_qs = UpdateQ.objects.filter(
        Q(portal_name__icontains=query)
    )[:10]

    portals = PortalInfo.objects.filter(
        Q(portal_name__icontains=query) |
        Q(group__icontains=query) |
        Q(branch__icontains=query) |
        Q(current_build__icontains=query) |
        Q(update_build__icontains=query) |
        Q(mdm_version__icontains=query)
    )[:10]

    return render(request, 'global_search_results.html', {
        'releases': releases,
        'release_histories': release_histories,
        'update_qs': update_qs,
        'portals': portals,
        'query': query,
    })
  
#@session_required
def portal_table(request):
    search_query = request.GET.get('search', '')
    current_sort = request.GET.get('sort', 'portal_name')
    page = request.GET.get('page', 1)
    rows_per_page = int(request.GET.get('rows', 20))

    # Filter only items with purge_status = False
    queryset = PortalInfo.objects.filter(purge_status=False)

    if search_query:
        queryset = queryset.filter(
            Q(portal_name__icontains=search_query) |
            Q(group__icontains=search_query) |
            Q(branch__icontains=search_query) |
            Q(current_build__icontains=search_query) |
            Q(update_build__icontains=search_query) |
            Q(mdm_version__icontains=search_query)
        )
    
    queryset = queryset.order_by(current_sort)
    
    smart_paginator = SmartPaginator(queryset, page, rows_per_page)
    
    total_items = smart_paginator.total_items
    start_item = smart_paginator.start_item
    end_item = smart_paginator.end_item
    page_range = smart_paginator.page_range
    
    context = {
        'portals': smart_paginator.page_obj,
        'search_query': search_query,
        'current_sort': current_sort,
        'rows_per_page': rows_per_page,
        'total_items': total_items,
        'start_item': start_item,
        'end_item': end_item,
        'page_range': page_range
    }
    return render(request, 'portalinfo.html', context)

#@session_required
def analytics_view(request):

    releases_query = Releases.objects.values('group')
    releases_by_group = []
    
    for group in releases_query.values('group').distinct():
        group_name = group['group']
        count = Releases.objects.filter(group=group_name).count()
        releases_by_group.append({
            'group': group_name,
            'count': count
        })
    
    portals_query = PortalInfo.objects.filter(purge_status=False).values('group')

    portals_by_group = []
    
    for group in portals_query.values('group').distinct():
        group_name = group['group']
        count = PortalInfo.objects.filter(group=group_name, purge_status=False).count()
        portals_by_group.append({
            'group': group_name,
            'count': count
        })

    groups = PortalInfo.objects.filter(purge_status=False).values_list('group', flat=True).distinct()
    update_status_by_group = []
    
    for group_name in groups:
        group_portals = PortalInfo.objects.filter(group=group_name, purge_status=False)
        
        updated_count = 0
        not_updated_count = 0
        
        for portal in group_portals:
            if portal.current_build == portal.update_build:
                updated_count += 1
            else:
                not_updated_count += 1
        
        update_status_by_group.append({
            'group': group_name,
            'updated': updated_count,
            'not_updated': not_updated_count
        })
    
    context = {
        'releases_by_group': json.dumps(releases_by_group),
        'portals_by_group': json.dumps(portals_by_group),
        'update_status_by_group': json.dumps(update_status_by_group),
    }
    return render(request, 'analytics.html', context)

def statusapp(request):
    return HttpResponse(status=200)
def ratelimiting():
    try:
        rateobj = UpdateQueue.objects.get(id=1)
    except:
        UpdateQueue(count=0,checktime=datetime.now(pytz.utc)).save()
        rateobj = UpdateQueue.objects.get(id=1)
    queuecount = rateobj.count
    lastcheck = rateobj.checktime
    now = datetime.now(pytz.utc)

    if queuecount < settings.UPDATE_AVAILABLE_THROTTLE:
        rateobj.checktime = now
        rateobj.count = queuecount + 1
        rateobj.save()
        return True
    else:
        if ( now - lastcheck ) > timedelta(hours=6):
            rateobj.checktime = now
            rateobj.count = 1
            rateobj.save()
            return True
        else:
            return False



class ReleaseCheck(APIView):
    queryset = Releases.objects.all().order_by('-id')

    def get_query_values(self):

        groups = Releases.objects.values_list('group',flat = True).distinct()
        data = {'status':status.HTTP_200_OK}
        for group in groups:
            if self.queryset.filter(group=group,enabled=True):
                query_list = self.queryset.filter(group=group,enabled=True).values('release_name','release_date','enabled','group')
                for i in query_list:
                    group = i['group']
                    del i['group']
                    data[group] = i

            else:
                query_list = self.queryset.filter(group=group, enabled=False).values('release_name', 'release_date', 'enabled','group')[:1]
                for i in query_list:
                    group = i['group']
                    del i['group']
                    data[group] = i
        return data


    def get(self,request,*args,**kwargs):
        data = self.get_query_values()
        
        return Response(data)


class ReleaseView(generics.ListCreateAPIView):
    serializer_class = ReleaseSerializer
    queryset = Releases.objects.all().order_by('-id')

    def post(self, request, *args, **kwargs):
        """
            release details
            :param request: release details
            :param kwargs: NA
            :return: release details
        """
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {'data': serializer.data, 'message': 'Successfully created', 'status': status.HTTP_201_CREATED},
                status=status.HTTP_201_CREATED)
        return Response(
            {'errors': serializer.errors, 'status': status.HTTP_400_BAD_REQUEST},
            status=status.HTTP_400_BAD_REQUEST)

class UpdateCheckSerializer(APIView):
    serializer_class = UpdateCheckSerializer


    def full_release_name(self,group):
        try:
            release_name = Releases.objects.filter(group=group,enabled=True).last().release_name
        except Exception as e:
            release_name = '0'
        return release_name

    def release_name(self,group):
        try:
            release_name = Releases.objects.filter(group=group,enabled=True).last().release_name[12:].replace('_', '.')
        except Exception as e:
            release_name = '0'
        return release_name

    def deleteq(self,portal_name,available_build_number):
        UpdateQ.objects.filter(portal_name=portal_name,available_build_number=available_build_number).delete()
    
    def checksum_check(self,release_name):
        try:
            checksum = ReleaseHistory.objects.filter(release_name=release_name).last().checksum
        except Exception as e:
            checksum = ''
        return checksum

        

    # checking portal update status
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        logger.info("connection initiated from portal %s" %(request.data.get('portalname','unknown')))
        logger.info("portal:%s build:%s group:%s branch:%s" %(request.data.get('portalname','unknown'),request.data.get('build','unknown'),request.data.get('group','unknown'),request.data.get('branch','unknown')))

        portalinfo_obj,created = PortalInfo.objects.get_or_create(portal_name=request.data.get('portalname','unknown'))
        portalinfo_obj.group = request.data.get('group','unknown')
        portalinfo_obj.branch = request.data.get('branch','unknown')
        portalinfo_obj.current_build = request.data.get('build','unknown')
        portalinfo_obj.mdm_version = request.data.get('version','unknown')

        if serializer.is_valid():
            if request.data['branch'] == 'master':
                group = request.data['group']
                release_name = self.release_name(group)
                full_release_name = self.full_release_name(group)
                checksum = self.checksum_check(full_release_name)
                version = request.data['build'][12:].replace('_', '.')
                # self.deleteq(request.data.get('portalname','unknown'),request.data.get('build','unknown'))

                if LooseVersion(version) < LooseVersion(release_name):
                    if ratelimiting() or not serializer.validated_data.get('ratelimit',True):
                        package = "HEXNODE_%s_update.tar.gz" %(release_name.replace('.','_'))
                        data = {'update': True,'package': package, 'checksum':checksum}
                        portalinfo_obj.update_build = full_release_name 
                        portalinfo_obj.update_queue = True

                        # UpdateQ.objects.get_or_create(portal_name=request.data.get('portalname','unknown'), current_build=request.data.get('build','unknown'),available_build_number=full_release_name)

                        logger.info("portal %s intimated with update using package %s" %(request.data.get('portalname','unknown'),package))
                    else:
                        data = {'update': False}
                else:
                    portalinfo_obj.update_build = ''
                    portalinfo_obj.update_queue = False
                    data = {'update': False}
            else:
                data = {'update': False}
        else:
            data = serializer.errors
        portalinfo_obj.save()
        return Response(data)


class ReleaseHistoryApi(generics.ListCreateAPIView):
    serializer_class = ReleaseHistorySerializer
    queryset = ReleaseHistory.objects.all()
    def post(self, request, *args, **kwargs):
        """
            release history details
            :param request: release hoistory details
            :param kwargs: NA
            :return: release history details
        """
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {'data': serializer.data, 'message': 'Successfully created', 'status': status.HTTP_201_CREATED},
                status=status.HTTP_201_CREATED)
        return Response(
            {'errors': serializer.errors, 'status': status.HTTP_400_BAD_REQUEST},
            status=status.HTTP_400_BAD_REQUEST)

class PurgeStatusApi(generics.CreateAPIView):
    serializer_class = PurgeSerializer

    def post(self, request, *args, **kwargs):
        return self.create(request, *args, **kwargs)
        
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        portals = serializer.validated_data['portals']
        updated = []
        for name in portals:
            try:
                portal = PortalInfo.objects.get(portal_name=name)
                portal.purge_status = True
                portal.save(update_fields=['purge_status'])
                updated.append(name)
            except PortalInfo.DoesNotExist:
                continue
        return Response({'purged':updated}, status=status.HTTP_200_OK)




class UpdateQueueService(APIView):
    permission_classes = (IsAuthenticated,)
    
    def post(self,request):
        queuecount = UpdateQ.objects.all().count() 
        now = datetime.now(pytz.utc)
        request_type = request.data.get('type','dequeue')
        data = {'status': False}

        if request_type == 'dequeue':
            logger.info("update slot completed by portal %s" %(request.data.get('portalname','unknown')))
            UpdateQ.objects.filter(portal_name=request.data.get('portalname','unknown')).delete()
            data['status'] = True

        elif request_type == 'enqueue':
            logger.info("requesting update slot by portal %s" %(request.data.get('portalname','unknown')))
            if queuecount < settings.UPDATE_THROTTLE:
                slot = queuecount + 1
                portalQ_obj,created = UpdateQ.objects.get_or_create(portal_name=request.data.get('portalname','unknown'))
                if created:
                    portalQ_obj.slot = slot
                else:
                    slot = portalQ_obj.slot
                portalQ_obj.request_time = now
                portalQ_obj.save()

                data['slot'] = slot
                data['status'] = True
                logger.info("portal %s given with update slot %s" %(request.data.get('portalname','unknown'),slot))
            else:
                logger.info("update queue exceeded limit of %s" %(settings.UPDATE_THROTTLE))
                logger.info("removing slots for requests older than 2 hours")
                old_slot_time = now - timedelta(hours=2)
                UpdateQ.objects.filter(request_time__lt=old_slot_time).delete()
        else:
            logger.error("unknown request type received from portal %s" %(request.data.get('portalname','unknown')))

        return Response(data)
