-- SQP Legal Consulting: perfiles de Auth, almacenamiento y RLS.
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

create table if not exists public.sqp_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  name text not null default '',
  role text not null default 'EXECUTIVE' check (role in ('ADMIN','SUPERVISOR','EXECUTIVE','VIEWER')),
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create table if not exists public.sqp_app_data (
  bucket text not null check (bucket in ('clients','requests','financings','audit','config','counters')),
  id text not null,
  owner_id uuid references auth.users(id) on delete set null,
  payload jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (bucket,id)
);

create or replace function private.current_sqp_role()
returns text language sql stable security definer set search_path=''
as $$
 select p.role from public.sqp_profiles p
 where p.id=(select auth.uid()) and p.active=true limit 1
$$;
revoke all on function private.current_sqp_role() from public,anon;
grant execute on function private.current_sqp_role() to authenticated;

create or replace function private.handle_new_sqp_user()
returns trigger language plpgsql security definer set search_path=''
as $$
declare requested_role text;
begin
 requested_role:=new.raw_app_meta_data->>'role';
 if requested_role is null or requested_role not in ('ADMIN','SUPERVISOR','EXECUTIVE','VIEWER') then requested_role:='EXECUTIVE'; end if;
 insert into public.sqp_profiles(id,email,name,role)
 values(new.id,coalesce(new.email,''),coalesce(new.raw_user_meta_data->>'full_name',split_part(coalesce(new.email,''),'@',1)),requested_role)
 on conflict(id) do update set email=excluded.email;
 return new;
end;
$$;
revoke all on function private.handle_new_sqp_user() from public,anon,authenticated;
create trigger on_auth_user_created_sqp_profile after insert on auth.users
for each row execute function private.handle_new_sqp_user();

create or replace function private.protect_sqp_financing_payments()
returns trigger language plpgsql set search_path=''
as $$
declare old_payment jsonb; new_payment jsonb; old_paid numeric; new_paid numeric; scheduled numeric; expected_status text;
begin
 if old.bucket in ('clients','requests') and new.payload->>'executiveId' is not null
    and new.owner_id is distinct from (new.payload->>'executiveId')::uuid then
   raise exception 'El responsable debe coincidir con el propietario';
 end if;
 if private.current_sqp_role()<>'EXECUTIVE' or old.bucket<>'financings' then return new; end if;
 if (new.payload-array['payments','status']) is distinct from (old.payload-array['payments','status'])
    or jsonb_typeof(old.payload->'payments')<>'array' or jsonb_typeof(new.payload->'payments')<>'array'
    or jsonb_array_length(old.payload->'payments')<>jsonb_array_length(new.payload->'payments') then
   raise exception 'Ejecutivos solo pueden actualizar pagos';
 end if;
 for old_payment in select value from jsonb_array_elements(old.payload->'payments') loop
  select value into new_payment from jsonb_array_elements(new.payload->'payments') where value->>'id'=old_payment->>'id';
  if new_payment is null then raise exception 'No se permite eliminar cuotas'; end if;
  if (new_payment-array['paidAmount','paidDate','status','daysLate','method','notes','registeredById'])
     is distinct from (old_payment-array['paidAmount','paidDate','status','daysLate','method','notes','registeredById']) then
    raise exception 'No se permite modificar los términos de una cuota';
  end if;
  old_paid:=coalesce((old_payment->>'paidAmount')::numeric,0);
  new_paid:=coalesce((new_payment->>'paidAmount')::numeric,0);
  scheduled:=coalesce((new_payment->>'scheduledAmount')::numeric,0);
  if new_paid<old_paid or new_paid>scheduled then raise exception 'Pago inválido'; end if;
 end loop;
 select case when count(*)>0 and bool_and(value->>'status'='PAID') then 'PAID'
   when bool_or(value->>'status'='OVERDUE') then 'OVERDUE'
   when bool_or(value->>'status' in ('LATE','PARTIAL')) then 'LATE' else 'ACTIVE' end
 into expected_status from jsonb_array_elements(new.payload->'payments');
 if new.payload->>'status' is distinct from expected_status then raise exception 'Estado de financiamiento inválido'; end if;
 return new;
end;
$$;
revoke all on function private.protect_sqp_financing_payments() from public,anon,authenticated;
create trigger protect_sqp_financing_payments before update on public.sqp_app_data
for each row execute function private.protect_sqp_financing_payments();

alter table public.sqp_profiles enable row level security;
alter table public.sqp_app_data enable row level security;
revoke all on public.sqp_profiles from anon,authenticated;
grant select,update on public.sqp_profiles to authenticated;
grant select,insert,update on public.sqp_app_data to authenticated;

create policy "SQP staff can read profiles" on public.sqp_profiles for select to authenticated
using(private.current_sqp_role() in ('ADMIN','SUPERVISOR','EXECUTIVE','VIEWER'));
create policy "SQP admins can manage profiles" on public.sqp_profiles for update to authenticated
using(private.current_sqp_role()='ADMIN') with check(private.current_sqp_role()='ADMIN');
create policy "SQP staff can read app data" on public.sqp_app_data for select to authenticated
using(private.current_sqp_role() in ('ADMIN','SUPERVISOR','EXECUTIVE','VIEWER'));
create policy "SQP permitted app data inserts" on public.sqp_app_data for insert to authenticated
with check(
 (private.current_sqp_role() in ('ADMIN','SUPERVISOR') and bucket in ('clients','requests','financings','config','counters'))
 or (private.current_sqp_role()='EXECUTIVE' and bucket in ('clients','requests','audit','counters') and owner_id=(select auth.uid()))
 or (private.current_sqp_role() in ('ADMIN','SUPERVISOR','EXECUTIVE','VIEWER') and bucket='audit' and owner_id=(select auth.uid()))
);
create policy "SQP permitted app data updates" on public.sqp_app_data for update to authenticated
using(private.current_sqp_role()='ADMIN'
 or (private.current_sqp_role()='SUPERVISOR' and bucket in ('clients','requests','financings','config','counters'))
 or (private.current_sqp_role()='EXECUTIVE' and bucket='clients' and owner_id=(select auth.uid()))
 or (private.current_sqp_role()='EXECUTIVE' and bucket='financings' and owner_id=(select auth.uid()))
 or (private.current_sqp_role()='EXECUTIVE' and bucket='counters'))
with check(private.current_sqp_role()='ADMIN'
 or (private.current_sqp_role()='SUPERVISOR' and bucket in ('clients','requests','financings','config','counters'))
 or (private.current_sqp_role()='EXECUTIVE' and bucket='clients' and owner_id=(select auth.uid()))
 or (private.current_sqp_role()='EXECUTIVE' and bucket='financings' and owner_id=(select auth.uid()))
 or (private.current_sqp_role()='EXECUTIVE' and bucket='counters'));



alter table public.sqp_app_data drop constraint sqp_app_data_bucket_check;
alter table public.sqp_app_data add constraint sqp_app_data_bucket_check check(bucket in ('clients','requests','financings','audit','config','counters','quotes','quote_templates','suggestions'));
grant delete on public.sqp_app_data to authenticated;
drop policy "SQP permitted app data inserts" on public.sqp_app_data;
drop policy "SQP permitted app data updates" on public.sqp_app_data;
create policy "SQP permitted app data inserts" on public.sqp_app_data for insert to authenticated with check (
 (private.current_sqp_role() in ('ADMIN','SUPERVISOR') and bucket in ('clients','requests','financings','config','counters','quotes','quote_templates','suggestions'))
 or (private.current_sqp_role()='EXECUTIVE' and bucket in ('clients','requests','audit','counters','quotes','quote_templates','suggestions') and owner_id=(select auth.uid()))
 or (private.current_sqp_role() in ('ADMIN','SUPERVISOR','EXECUTIVE','VIEWER') and bucket='audit' and owner_id=(select auth.uid()))
);
create policy "SQP permitted app data updates" on public.sqp_app_data for update to authenticated
using (
 private.current_sqp_role()='ADMIN'
 or (private.current_sqp_role()='SUPERVISOR' and bucket in ('clients','requests','financings','config','counters','quotes','quote_templates','suggestions'))
 or (private.current_sqp_role()='EXECUTIVE' and bucket in ('clients','financings','quotes','quote_templates','counters','suggestions') and (bucket='counters' or owner_id=(select auth.uid())))
)
with check (
 private.current_sqp_role()='ADMIN'
 or (private.current_sqp_role()='SUPERVISOR' and bucket in ('clients','requests','financings','config','counters','quotes','quote_templates','suggestions'))
 or (private.current_sqp_role()='EXECUTIVE' and bucket in ('clients','financings','quotes','quote_templates','counters','suggestions') and (bucket='counters' or owner_id=(select auth.uid())))
);
create policy "SQP permitted app data deletes" on public.sqp_app_data for delete to authenticated
using (
 (private.current_sqp_role() in ('ADMIN','SUPERVISOR') and bucket in ('clients','requests','quotes','quote_templates','suggestions'))
 or (private.current_sqp_role()='EXECUTIVE' and bucket in ('clients','quotes','quote_templates','suggestions') and owner_id=(select auth.uid()))
);
create index sqp_app_data_owner on public.sqp_app_data(owner_id);
create function public.next_sqp_quote_number() returns bigint language plpgsql security invoker set search_path='' as $$
declare next_value bigint; quote_highwater bigint;
begin
 if auth.uid() is null or coalesce(private.current_sqp_role(),'') not in ('ADMIN','SUPERVISOR','EXECUTIVE') then
  raise exception 'SQP role cannot issue quotes' using errcode='42501';
 end if;
 select coalesce(max(((regexp_match(payload->>'quoteNumber','^COT-[0-9]{4}-([0-9]+)$'))[1])::bigint),0)
 into quote_highwater from public.sqp_app_data where bucket='quotes';
 insert into public.sqp_app_data(bucket,id,owner_id,payload,updated_at)
 values('counters','quote',auth.uid(),jsonb_build_object('value',quote_highwater+1),now())
 on conflict(bucket,id) do update set payload=jsonb_set(public.sqp_app_data.payload,'{value}',to_jsonb(greatest(coalesce(nullif(public.sqp_app_data.payload->>'value','')::bigint,0),quote_highwater)+1),true),updated_at=now()
 returning (payload->>'value')::bigint into next_value;
 return next_value;
end;
$$;
revoke all on function public.next_sqp_quote_number() from public,anon;
grant execute on function public.next_sqp_quote_number() to authenticated;
