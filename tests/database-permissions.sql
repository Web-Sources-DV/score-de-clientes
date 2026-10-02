
begin;
select set_config('sqp_test.admin',(select id::text from public.sqp_profiles where role='ADMIN' and active limit 1),true);
select set_config('sqp_test.executive',gen_random_uuid()::text,true);
select set_config('sqp_test.viewer',gen_random_uuid()::text,true);
select set_config('sqp_test.counter',coalesce((select payload::text from public.sqp_app_data where bucket='counters' and id='default'),''),true);
insert into auth.users(id,aud,role,email,raw_app_meta_data,raw_user_meta_data)
values(current_setting('sqp_test.executive')::uuid,'authenticated','authenticated','migration-executive@example.invalid','{"role":"EXECUTIVE"}','{}'),
(current_setting('sqp_test.viewer')::uuid,'authenticated','authenticated','migration-viewer@example.invalid','{"role":"VIEWER"}','{}');
insert into public.sqp_app_data(bucket,id,owner_id,payload) values
('quotes','migration-admin-quote',current_setting('sqp_test.admin')::uuid,'{"id":"migration-admin-quote","quoteNumber":"COT-2026-0040"}'),
('financings','migration-financing',current_setting('sqp_test.executive')::uuid,'{"id":"migration-financing","principal":100,"status":"ACTIVE","payments":[{"id":"one","paidAmount":0,"scheduledAmount":100,"status":"PENDING"}]}');
set local role authenticated;
select set_config('request.jwt.claim.sub',current_setting('sqp_test.executive'),true);
do $$
declare first_number bigint; second_number bigint;
begin
 if private.current_sqp_role()<>'EXECUTIVE' then raise exception 'Executive profile failed'; end if;
 first_number:=public.next_sqp_quote_number(); second_number:=public.next_sqp_quote_number();
 if first_number<>41 or second_number<>42 then raise exception 'Quote numbering failed'; end if;
 if (select payload::text from public.sqp_app_data where bucket='counters' and id='default') is distinct from current_setting('sqp_test.counter') then raise exception 'Financing counter changed'; end if;
 insert into public.sqp_app_data(bucket,id,owner_id,payload) values('quotes','migration-executive-quote',auth.uid(),'{"id":"migration-executive-quote"}');
 update public.sqp_app_data set payload='{"id":"migration-admin-quote","tampered":true}' where bucket='quotes' and id='migration-admin-quote';
 if exists(select 1 from public.sqp_app_data where bucket='quotes' and id='migration-admin-quote' and payload ? 'tampered') then raise exception 'Executive changed another user quote'; end if;
 update public.sqp_app_data set payload=jsonb_set(jsonb_set(payload,'{payments,0,paidAmount}','50'),'{payments,0,status}','"PARTIAL"')||'{"status":"LATE"}'::jsonb where bucket='financings' and id='migration-financing';
 begin
  update public.sqp_app_data set payload=jsonb_set(payload,'{principal}','200') where bucket='financings' and id='migration-financing';
  raise exception 'Executive changed financing terms';
 exception when others then if sqlerrm='Executive changed financing terms' then raise; end if; end;
 delete from public.sqp_app_data where bucket='quotes' and id='migration-executive-quote';
 if exists(select 1 from public.sqp_app_data where bucket='quotes' and id='migration-executive-quote') then raise exception 'Executive cannot delete own quote'; end if;
end;
$$;
select set_config('request.jwt.claim.sub',current_setting('sqp_test.viewer'),true);
do $$ begin
 if private.current_sqp_role()<>'VIEWER' then raise exception 'Viewer profile failed'; end if;
 begin
  perform public.next_sqp_quote_number(); raise exception 'Viewer issued quote';
 exception when insufficient_privilege then null; end;
 begin
  insert into public.sqp_app_data(bucket,id,owner_id,payload) values('quotes','migration-viewer-quote',auth.uid(),'{}');
  raise exception 'Viewer wrote quote';
 exception when insufficient_privilege then null; end;
end; $$;
reset role;
update public.sqp_profiles set active=false where id=current_setting('sqp_test.executive')::uuid;
set local role authenticated;
select set_config('request.jwt.claim.sub',current_setting('sqp_test.executive'),true);
do $$ begin
 if exists(select 1 from public.sqp_app_data) then raise exception 'Inactive account can read commercial data'; end if;
end; $$;
reset role;
rollback;
select 'PASS: shared quote numbering, isolated finance counters, executive ownership, protected payments, viewer, inactive profiles' as result;
