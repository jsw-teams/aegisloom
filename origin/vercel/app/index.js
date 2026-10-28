export default { async fetch(request) {
  if (new URL(request.url).pathname === '/health') return Response.json({ok:true});
  return Response.json({error:'business_route_not_configured'},{status:404});
}};
