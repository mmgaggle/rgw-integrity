#!/usr/bin/env python3
"""
seed_listing_corpus.py: buckets whose objects exercise the native listing,
for compare_listing.sh to list both ways: sizes around the head and stripe
boundaries, awkward keys, multipart uploads ( open ones too, and parts
larger than a stripe ), copies within and across buckets, versions and
delete markers and null versions, a tenant's bucket, an index resharded to
many shards, and appendable objects.

    CEPH_BUILD=~/ceph/build python tests/seed_listing_corpus.py [prefix]

The buckets are named <prefix>-*, lc-* by default; existing ones are
removed first.  Prints the buckets it made, one per line.
"""
import os
import subprocess
import sys
import urllib.request

import boto3
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.credentials import Credentials

B = os.environ['CEPH_BUILD']
EP = os.environ.get('S3_ENDPOINT', 'http://localhost:8000')
AK = os.environ.get('S3_ACCESS_KEY', '0555b35654ad1656d804')
SK = os.environ.get('S3_SECRET_KEY', 'h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q==')
P = sys.argv[1] if len(sys.argv) > 1 else 'lc'
MB = 1 << 20
TENANT, TENANT_AK, TENANT_SK = f'{P}t', f'{P}-tenant-ak', f'{P}-tenant-sk'


def admin(*args, check=True):
    r = subprocess.run([f'{B}/bin/radosgw-admin', '-c', f'{B}/ceph.conf', *args],
                       capture_output=True, text=True, cwd=B)
    if check and r.returncode:
        sys.exit(f'radosgw-admin {" ".join(args)}: {r.stderr.strip()[-500:]}')
    return r.stdout


def client(ak=AK, sk=SK):
    return boto3.client('s3', endpoint_url=EP, aws_access_key_id=ak, aws_secret_access_key=sk,
                        region_name='default',
                        config=Config(read_timeout=600, retries={'total_max_attempts': 1}))


def blob(n):
    return os.urandom(n)


def fresh(s3, bucket, qualified=None):
    admin('bucket', 'rm', f'--bucket={qualified or bucket}', '--purge-objects', check=False)
    s3.create_bucket(Bucket=bucket)
    print(qualified or bucket)


def multipart(s3, bucket, key, sizes, complete=True, copy_from=None):
    """An upload of parts of these sizes; a part given as a (bucket, key,
    first, last) tuple copies that range of another object."""
    up = s3.create_multipart_upload(Bucket=bucket, Key=key)['UploadId']
    parts = []
    for n, size in enumerate(sizes, 1):
        if isinstance(size, tuple):
            sb, sk, first, last = size
            r = s3.upload_part_copy(Bucket=bucket, Key=key, UploadId=up, PartNumber=n,
                                    CopySource={'Bucket': sb, 'Key': sk}, CopySourceRange=f'bytes={first}-{last}')
            parts.append({'PartNumber': n, 'ETag': r['CopyPartResult']['ETag']})
        else:
            r = s3.upload_part(Bucket=bucket, Key=key, UploadId=up, PartNumber=n, Body=blob(size))
            parts.append({'PartNumber': n, 'ETag': r['ETag']})
    if complete:
        s3.complete_multipart_upload(Bucket=bucket, Key=key, UploadId=up, MultipartUpload={'Parts': parts})
    return up


def append(bucket, key, position, body):
    """RGW's appendable objects: PUT ?append&position=N"""
    url = f'{EP}/{bucket}/{urllib.request.quote(key)}?append&position={position}'
    req = AWSRequest(method='PUT', url=url, data=body)
    req.headers['Content-Length'] = str(len(body))
    S3SigV4Auth(Credentials(AK, SK), 's3', 'default').add_auth(req)
    with urllib.request.urlopen(urllib.request.Request(url, data=body, method='PUT', headers=dict(req.headers))) as r:
        r.read()


s3 = client()

# sizes around the 4 MiB head and stripe, and keys that need escaping, a
# locator, or look like a namespace
b = f'{P}-sizes'
fresh(s3, b)
for size in (0, 1, 4 * MB - 1, 4 * MB, 4 * MB + 1, 8 * MB, 13 * MB + 7):
    s3.put_object(Bucket=b, Key=f'size-{size}', Body=blob(size))
for key in ('_under', '__double', '_multipart_fake', '_shadow_fake.1', 'ключ/日本語/😀', 'a b+c%20d&e',
            'dir/sub/', 'x[y]', 'dots...meta', 'k' * 900, ' leading space'):
    s3.put_object(Bucket=b, Key=key, Body=blob(5 * MB))

# multipart: parts of a stripe or less, parts of several stripes, a copied
# part, one tiny part; uploads left open, one with a part uploaded twice
b = f'{P}-mp'
fresh(s3, b)
multipart(s3, b, 'mp-small-parts', [5 * MB, 5 * MB, 1 * MB])
multipart(s3, b, 'mp-big-parts', [9 * MB, 9 * MB, 3 * MB])
multipart(s3, b, 'mp-one-byte', [1])
multipart(s3, b, '_mp-under', [5 * MB, 2 * MB])
multipart(s3, b, 'mp-copied-part', [(f'{P}-sizes', f'size-{13 * MB + 7}', 0, 13 * MB + 6), 2 * MB])
multipart(s3, b, 'open-big-parts', [9 * MB, 5 * MB], complete=False)
multipart(s3, b, 'open-no-parts', [], complete=False)
up = multipart(s3, b, 'open-reuploaded', [5 * MB, 6 * MB], complete=False)
s3.upload_part(Bucket=b, Key='open-reuploaded', UploadId=up, PartNumber=2, Body=blob(9 * MB))

# copies: in the same bucket ( a shared tail ), from another bucket ( the
# tail stays in it ), of a multipart object, of a copy, onto itself
b = f'{P}-copies'
fresh(s3, b)
s3.put_object(Bucket=b, Key='src', Body=blob(13 * MB))
s3.copy_object(Bucket=b, Key='copy-same', CopySource={'Bucket': b, 'Key': 'src'})
s3.copy_object(Bucket=b, Key='copy-of-copy', CopySource={'Bucket': b, 'Key': 'copy-same'})
s3.copy_object(Bucket=b, Key='copy-cross', CopySource={'Bucket': f'{P}-sizes', 'Key': 'size-8388608'})
s3.copy_object(Bucket=b, Key='copy-mp', CopySource={'Bucket': f'{P}-mp', 'Key': 'mp-big-parts'})
s3.copy_object(Bucket=b, Key='copy-small', CopySource={'Bucket': f'{P}-sizes', 'Key': 'size-1'})
s3.copy_object(Bucket=b, Key='src', CopySource={'Bucket': b, 'Key': 'src'},
               Metadata={'k': 'v'}, MetadataDirective='REPLACE')

# versions: a null version from before versioning, versions of every size, a
# delete marker over versions and one alone, a versioned multipart object,
# a copy in, and a null version written while versioning was suspended
b = f'{P}-versioned'
fresh(s3, b)
s3.put_object(Bucket=b, Key='pre', Body=blob(13 * MB))
s3.put_object(Bucket=b, Key='pre-kept', Body=blob(6 * MB))
s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={'Status': 'Enabled'})
s3.put_object(Bucket=b, Key='pre', Body=blob(5 * MB))
for size in (13 * MB, 1, 0):
    s3.put_object(Bucket=b, Key='v', Body=blob(size))
s3.put_object(Bucket=b, Key='_v-under', Body=blob(5 * MB))
s3.delete_object(Bucket=b, Key='v')
s3.put_object(Bucket=b, Key='gone', Body=blob(5 * MB))
s3.delete_object(Bucket=b, Key='gone')
s3.delete_object(Bucket=b, Key='never-was')
multipart(s3, b, 'mpv', [5 * MB, 3 * MB])
multipart(s3, b, 'mpv', [9 * MB])
s3.copy_object(Bucket=b, Key='copied-in', CopySource={'Bucket': f'{P}-copies', 'Key': 'src'})
s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={'Status': 'Suspended'})
s3.put_object(Bucket=b, Key='pre', Body=blob(7 * MB))
s3.put_object(Bucket=b, Key='suspended-new', Body=blob(5 * MB))

# a copy out of a versioned bucket: the tail keeps the source's instance
s3.copy_object(Bucket=f'{P}-copies', Key='copy-from-version', CopySource={'Bucket': b, 'Key': 'mpv'})

# a tenant's bucket
admin('user', 'rm', f'--tenant={TENANT}', f'--uid={P}u', '--purge-data', check=False)
admin('user', 'create', f'--tenant={TENANT}', f'--uid={P}u', '--display-name=listing corpus tenant',
      f'--access-key={TENANT_AK}', f'--secret={TENANT_SK}')
t = client(TENANT_AK, TENANT_SK)
b = f'{P}-tenant'
fresh(t, b, f'{TENANT}/{b}')
t.put_object(Bucket=b, Key='obj', Body=blob(13 * MB))
t.put_object(Bucket=b, Key='_under', Body=blob(1))
multipart(t, b, 'mp', [5 * MB, 5 * MB])
multipart(t, b, 'open', [9 * MB], complete=False)

# many shards, resharded twice: generation 2 of the index
b = f'{P}-shards'
fresh(s3, b)
admin('bucket', 'reshard', f'--bucket={b}', '--num-shards=7', '--yes-i-really-mean-it')
for i in range(150):
    s3.put_object(Bucket=b, Key=f'k{i:04d}', Body=blob(5 * MB if i % 25 == 0 else 100))
multipart(s3, b, 'mp', [5 * MB, 1 * MB])
multipart(s3, b, 'open', [9 * MB], complete=False)
admin('bucket', 'reshard', f'--bucket={b}', '--num-shards=13', '--yes-i-really-mean-it')
for i in range(150, 300):
    s3.put_object(Bucket=b, Key=f'k{i:04d}', Body=blob(100))

# appendable objects: each append a part of its own
b = f'{P}-append'
fresh(s3, b)
pos = 0
for size in (3 * MB, 3 * MB, 5 * MB, 1):
    append(b, 'appended', pos, blob(size))
    pos += size
append(b, 'appended-once', 0, blob(6 * MB))
