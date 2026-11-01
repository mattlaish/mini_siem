# Entity Context API Enhancement

Extends existing SOC investigation workflow.

Planned endpoints:

GET /api/entities/<type>/<value>

GET /api/tickets/<id>/entities

GET /api/entities/<id>/relationships

The design keeps entity context separate from raw event storage.
