-- NDIAYE CHINA SHOP — schéma initial sécurisé
-- À exécuter dans Supabase > SQL Editor.
-- Ne jamais désactiver RLS et ne jamais exposer une clé sb_secret/service_role.

create table if not exists public.shop_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create or replace function public.is_shop_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.shop_admins a
    where a.user_id = (select auth.uid())
  );
$$;

revoke all on function public.is_shop_admin() from public;
grant execute on function public.is_shop_admin() to anon, authenticated;

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text not null default '',
  category text not null default 'maison',
  price_fcfa integer,
  stock integer not null default 0 check (stock >= 0),
  image_url text,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint products_price_nonnegative check (price_fcfa is null or price_fcfa >= 0)
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  customer_name text not null,
  customer_phone text not null,
  customer_area text not null,
  customer_note text not null default '',
  items jsonb not null,
  status text not null default 'nouvelle'
    check (status in ('nouvelle','confirmée','en_preparation','expédiée','livrée','annulée')),
  created_at timestamptz not null default now()
);

alter table public.shop_admins enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;

drop policy if exists "Public can read active products" on public.products;
create policy "Public can read active products"
on public.products for select to anon, authenticated
using (is_active = true or public.is_shop_admin());

drop policy if exists "Admins manage products" on public.products;
create policy "Admins manage products"
on public.products for all to authenticated
using (public.is_shop_admin())
with check (public.is_shop_admin());

drop policy if exists "Public can submit orders" on public.orders;
create policy "Public can submit orders"
on public.orders for insert to anon, authenticated
with check (
  length(trim(customer_name)) between 2 and 120
  and length(trim(customer_phone)) between 6 and 30
  and length(trim(customer_area)) between 2 and 160
  and jsonb_typeof(items) = 'array'
  and jsonb_array_length(items) between 1 and 30
  and status = 'nouvelle'
);

drop policy if exists "Admins read and manage orders" on public.orders;
create policy "Admins read and manage orders"
on public.orders for all to authenticated
using (public.is_shop_admin())
with check (public.is_shop_admin());

drop policy if exists "Admins read admin list" on public.shop_admins;
create policy "Admins read admin list"
on public.shop_admins for select to authenticated
using (public.is_shop_admin());

grant select on public.products to anon, authenticated;
grant insert, update, delete on public.products to authenticated;
grant insert on public.orders to anon, authenticated;
grant select, update, delete on public.orders to authenticated;
grant select on public.shop_admins to authenticated;

-- Après création de ton compte dans Authentication > Users,
-- copie son User UID et exécute cette commande en remplaçant UUID_ICI :
-- insert into public.shop_admins (user_id) values ('UUID_ICI');
