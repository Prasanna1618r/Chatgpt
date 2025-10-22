I'm using Django1.6 and python2.7

# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models
from datetime import date, datetime
from django.utils import timezone


class Releases(models.Model):
    release_name = models.TextField()
    release_date = models.DateTimeField(blank=True, null=True)
    group = models.CharField(max_length=50)
    enabled = models.BooleanField(default=True)
    class Meta:
        unique_together = ('release_name','group')
    
class UpdateQueue(models.Model):
    count = models.IntegerField(default=0)
    checktime = models.DateTimeField(default=datetime.now()) 

class ReleaseHistory(models.Model):
    release_name = models.TextField()
    release_date = models.DateTimeField(blank=True, null=True)
    checksum = models.TextField(blank=True, null=True)
    commit_no = models.TextField(blank=True, null=True)
    remarks = models.TextField(blank=True, null=True)
    releasable = models.BooleanField(default=True)
    def __unicode__(self):
        return u"%s" % (self.release_name)

class UpdateQ(models.Model):
    portal_name = models.TextField()
    slot = models.IntegerField()
    request_time = models.DateTimeField(default=timezone.now())

class PortalInfo(models.Model):
    portal_name = models.TextField(unique=True)
    last_reported = models.DateTimeField(default=datetime.now())
    group = models.CharField(max_length=50)
    branch = models.TextField()
    current_build = models.TextField()
    update_build = models.TextField()
    mdm_version = models.TextField()
    update_queue = models.BooleanField(default=False)
    purge_status = models.BooleanField(default=False)

class CustomRelease(models.Model):
    custom_release_name = models.CharField(max_length=100)
    release_version = models.ForeignKey('ReleaseHistory')
    description = models.TextField(blank=True, null=True)
    date = models.DateTimeField(default=datetime.now())
    portals = models.ManyToManyField(PortalInfo, related_name='custom_releases')
    enabled = models.BooleanField(default=True)
    def __unicode__(self):
        return u"%s - %s" % (self.custom_release_name, self.version)

class PortalLatestRelease(models.Model):
    portal = models.OneToOneField('PortalInfo')
    latest_release = models.ForeignKey('CustomRelease')
    def __unicode__(self):
        return u"%s -> %s" % (self.portal.portal_name, self.latest_release.custom_release_name)

this is models.py 

def portal_table(request):
    search_query = request.GET.get('search', '')
    current_sort = request.GET.get('sort', 'portal_name')
    page = request.GET.get('page', 1)
    rows_per_page = int(request.GET.get('rows', 10))

    # Filter only items with purge_status = False
    queryset = PortalInfo.objects.filter(purge_status=False).select_related('portallatestrelease__latest_release')

    if search_query:
        queryset = queryset.filter(
            Q(portal_name__icontains=search_query) |
            Q(group__icontains=search_query) |
            Q(portallatestrelease__latest_release__custom_release_name__icontains=search_query) |
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

@never_cache
@session_required  
def customrelease_view(request):
    search_query = request.GET.get('search', '')
    current_sort = request.GET.get('sort', '-date')
    page = request.GET.get('page', 1)
    rows_per_page = int(request.GET.get('rows', 10))
    queryset = CustomRelease.objects.all()
    if search_query:
        queryset = queryset.filter(
            Q(custom_release_name__icontains=search_query) |
            Q(release_version__release_name__icontains=search_query) |
            Q(description__icontains=search_query) |
            Q(portals__portal_name__icontains=search_query)
        ).distinct()
    queryset = queryset.order_by(current_sort)
    smart_paginator = SmartPaginator(queryset, page, rows_per_page)
    page_obj = smart_paginator.page_obj
    release_versions = ReleaseHistory.objects.all().order_by('-id')
    context = {
        'custom_releases': page_obj, 
        'search_query': search_query,
        'current_sort': current_sort,
        'rows_per_page': rows_per_page,
        'total_items': smart_paginator.total_items,
        'start_item': smart_paginator.start_item,
        'end_item': smart_paginator.end_item,
        'page_range': smart_paginator.page_range,
        'release_versions': release_versions,
    }
    return render(request, 'customreleaseinfo.html', context)

@session_required  
def get_custom_versions(request):
    release_versions = ReleaseHistory.objects.all().order_by('-id')
    
    return render(request, 'customrelease_form.html', {
        'release_versions': release_versions
    })

def upload_custom_release(request):
    if request.method == 'POST':
        release_name = request.POST.get('release_name')
        description = request.POST.get('description')
        version_id = request.POST.get('version')
        csv_file = request.FILES.get('csv_file')
        if not (release_name and description and version_id and csv_file):
            request.GET = request.GET.copy()
            return customrelease_view(request)
        try:
            release_history = ReleaseHistory.objects.get(id=version_id)
        except ReleaseHistory.DoesNotExist:
            request.GET = request.GET.copy()
            return customrelease_view(request)
        text_file = TextIOWrapper(csv_file.file, encoding='utf-8')
        csv_reader = csv.reader(text_file)
        portal_names = [row[0].strip() for row in csv_reader if row and row[0].strip()]
        if not portal_names:
            request.GET = request.GET.copy()
            return customrelease_view(request)
        matched_portals = PortalInfo.objects.filter(portal_name__in=portal_names)
        custom_release = CustomRelease.objects.create(
            custom_release_name=release_name,
            release_version=release_history,  
            description=description,
            date=datetime.now()
        )
        if matched_portals.exists():
            custom_release.portals.add(*matched_portals)
            for portal in matched_portals:
                obj, created = PortalLatestRelease.objects.get_or_create(
                    portal=portal,
                    defaults={'latest_release': custom_release}
                )
                if not created:
                    obj.latest_release = custom_release
                    obj.save()
        return customrelease_view(request)

@require_POST
def toggle_customrelease_enabled(request):
    release_id = request.POST.get('release_id')
    
    if not release_id:
        response_data = {'success': False, 'error': 'Release ID not provided', 'release_id': release_id}
        return HttpResponse(json.dumps(response_data),
                            content_type='application/json', status=400)
    try:
        release = CustomRelease.objects.get(id=release_id)
    except CustomRelease.DoesNotExist:
        response_data = {'success': False, 'error': 'Release not found'}
        return HttpResponse(json.dumps(response_data),
                            content_type='application/json', status=404)
    if release.enabled:
        release.enabled = False
        release.save()
        PortalLatestRelease.objects.filter(latest_release=release).delete()
    else:
        release.enabled = True
        release.save()
    response_data = {'success': True, 'enabled': release.enabled}
    return HttpResponse(json.dumps(response_data),
                        content_type='application/json') 



this is views.py 


now i need to add one more table called portals while uploading the portals via form all the portals should be added in the portals table if the portal is not in the portals table and those portals should be displayed in the customrelease table for the particular custom_release these are mapped in the portallatestrelease need to add one more column in the portallatestrelease called portalinfo's portal if the portal name of the portal and portalinfo is matched then that added there if there is a portal in portal but not in the portalinfo we should show the portal in portallatestrelease in that portalinfo's portal should be - modify the code according to that and the custom release should be displayed in the portalinfo view
