#![cfg_attr(docsrs, feature(doc_cfg))]
extern crate proc_macro;

use proc_macro::TokenStream;

// Define dummy macro_attribute and macro_derive for stable rustc

#[cfg(not(feature = "frozen-abi"))]
#[proc_macro_attribute]
pub fn frozen_abi(_attrs: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[cfg(not(feature = "frozen-abi"))]
#[proc_macro_derive(AbiExample)]
pub fn derive_abi_sample(_item: TokenStream) -> TokenStream {
    "".parse().unwrap()
}

#[cfg(not(feature = "frozen-abi"))]
#[proc_macro_derive(AbiEnumVisitor)]
pub fn derive_abi_enum_visitor(_item: TokenStream) -> TokenStream {
    "".parse().unwrap()
}

#[cfg(not(feature = "frozen-abi"))]
#[proc_macro_derive(StableAbi)]
pub fn derive_stable_abi(_item: TokenStream) -> TokenStream {
    "".parse().unwrap()
}

#[cfg(feature = "frozen-abi")]
#[proc_macro_derive(StableAbi)]
pub fn derive_stable_abi(item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as Item);
    let (ident, generics) = match item {
        Item::Struct(s) => (s.ident, s.generics),
        Item::Enum(e) => (e.ident, e.generics),
        Item::Type(t) => (t.ident, t.generics),
        item => {
            return Error::new_spanned(
                item,
                "StableAbi can only be derived for struct, enum, or type alias",
            )
            .to_compile_error()
            .into();
        }
    };
    let generics = add_stable_abi_type_param_bounds(generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        #[automatically_derived]
        impl #impl_generics ::solana_frozen_abi::stable_abi::StableAbi for #ident #ty_generics #where_clause {
            fn random_with_context(
                rng: &mut (impl ::solana_frozen_abi::rand::RngCore + ?Sized),
                _ctx: (),
            ) -> Self {
                ::solana_frozen_abi::rand::Rng::random::<Self>(rng)
            }
        }
    };
    expanded.into()
}

#[cfg(not(feature = "frozen-abi"))]
#[proc_macro_derive(StableAbiSample, attributes(stable_abi_sample))]
pub fn derive_stable_abi_sample(_item: TokenStream) -> TokenStream {
    "".parse().unwrap()
}

#[cfg(feature = "frozen-abi")]
#[proc_macro_derive(StableAbiSample, attributes(stable_abi_sample))]
pub fn derive_stable_abi_sample(item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as Item);
    let expanded = match item {
        Item::Struct(input) => derive_stable_abi_sample_struct_type(input),
        Item::Enum(input) => derive_stable_abi_sample_enum_type(input),
        _ => Err(Error::new_spanned(
            item,
            "StableAbiSample can only be derived for struct or enum",
        )),
    };
    expanded.unwrap_or_else(|err| err.to_compile_error()).into()
}

#[cfg(feature = "frozen-abi")]
use proc_macro2::{Span, TokenStream as TokenStream2, TokenTree};
#[cfg(feature = "frozen-abi")]
use quote::{quote, ToTokens};
#[cfg(feature = "frozen-abi")]
use syn::{
    parse_macro_input, Attribute, Error, Expr, ExprLit, Fields, Ident, Item, ItemEnum, ItemStruct,
    ItemType, Lit, LitStr, Variant,
};

#[cfg(feature = "frozen-abi")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AbiSerializer {
    Bincode,
    Wincode,
}

#[cfg(feature = "frozen-abi")]
impl AbiSerializer {
    fn from_lit_str(lit: &LitStr) -> Result<Self, Error> {
        match lit.value().as_str() {
            "bincode" => Ok(Self::Bincode),
            "wincode" => Ok(Self::Wincode),
            other => Err(Error::new(
                lit.span(),
                format!(
                    "unsupported `abi_serializer` value `{other}`; expected `bincode` or `wincode`"
                ),
            )),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Bincode => "bincode",
            Self::Wincode => "wincode",
        }
    }

    fn serialize_expr(self) -> TokenStream2 {
        match self {
            Self::Bincode => quote! { ::solana_frozen_abi::bincode },
            Self::Wincode => quote! { ::solana_frozen_abi::wincode },
        }
    }
}

/// Parse the `abi_serializer` attribute value, which may be either a single
/// string literal (e.g. `"wincode"`) or a list of string literals
/// (e.g. `["bincode", "wincode"]`).
#[cfg(feature = "frozen-abi")]
fn parse_abi_serializers(expr: &Expr) -> Result<Vec<AbiSerializer>, Error> {
    fn lit_str(expr: &Expr) -> Result<&LitStr, Error> {
        match expr {
            // Unwrap the invisible group that wraps a `macro_rules!` `:literal`
            // fragment when it is interpolated into the attribute.
            Expr::Group(group) => lit_str(&group.expr),
            Expr::Lit(ExprLit {
                lit: Lit::Str(lit), ..
            }) => Ok(lit),
            other => Err(Error::new_spanned(
                other,
                "expected a string literal `abi_serializer` value",
            )),
        }
    }

    match expr {
        Expr::Array(array) => {
            if array.elems.is_empty() {
                return Err(Error::new_spanned(
                    array,
                    "`abi_serializer` list must not be empty",
                ));
            }
            array
                .elems
                .iter()
                .map(|elem| AbiSerializer::from_lit_str(lit_str(elem)?))
                .collect()
        }
        expr => Ok(vec![AbiSerializer::from_lit_str(lit_str(expr)?)?]),
    }
}

#[cfg(feature = "frozen-abi")]
enum RoundtripTest {
    No,
    WireOnly,
    EqAndWire,
}

#[cfg(feature = "frozen-abi")]
fn parse_roundtrip_test(value: Option<&LitStr>) -> Result<RoundtripTest, Error> {
    match value {
        None => Ok(RoundtripTest::WireOnly),
        Some(value) => match value.value().as_str() {
            "no" => Ok(RoundtripTest::No),
            "wire_only" => Ok(RoundtripTest::WireOnly),
            "eq_and_wire" => Ok(RoundtripTest::EqAndWire),
            _ => Err(Error::new_spanned(value, "unsupported `test_roundtrip` value; expected \"no\", \"wire_only\", or \"eq_and_wire\"")),
        },
    }
}

#[cfg(feature = "frozen-abi")]
fn filter_serde_attrs(attrs: &[Attribute]) -> bool {
    fn contains_skip(tokens: TokenStream2) -> bool {
        for token in tokens.into_iter() {
            match token {
                TokenTree::Group(group) => {
                    if contains_skip(group.stream()) {
                        return true;
                    }
                }
                TokenTree::Ident(ident) => {
                    if ident == "skip" {
                        return true;
                    }
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => (),
            }
        }

        false
    }

    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }

        if contains_skip(attr.to_token_stream()) {
            return true;
        }
    }

    false
}

#[cfg(feature = "frozen-abi")]
fn filter_allow_attrs(attrs: &mut Vec<Attribute>) {
    attrs.retain(|attr| {
        let ss = &attr.path().segments.first().unwrap().ident.to_string();
        ss.starts_with("allow")
    });
}

#[cfg(feature = "frozen-abi")]
struct StableAbiSampleOptions {
    with_expr: Option<TokenStream2>,
    ctx_expr: Option<TokenStream2>,
}

#[cfg(feature = "frozen-abi")]
fn parse_stable_abi_sample_options(field: &syn::Field) -> Result<StableAbiSampleOptions, Error> {
    let mut with_expr: Option<TokenStream2> = None;
    let mut ctx_expr: Option<TokenStream2> = None;
    for attr in &field.attrs {
        if !attr.path().is_ident("stable_abi_sample") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("with") {
                // reject duplicate `with` on the same field
                if with_expr.is_some() {
                    return Err(meta.error("duplicate `with` in `#[stable_abi_sample(...)]`"));
                }
                let value = meta.value()?.parse::<LitStr>()?;
                let expr = syn::parse_str::<Expr>(&value.value()).map_err(|err| {
                    Error::new(value.span(), format!("invalid `with` expression: {err}"))
                })?;
                with_expr = Some(quote! { #expr });
                Ok(())
            } else if meta.path.is_ident("ctx") {
                // reject duplicate `ctx` on the same field
                if ctx_expr.is_some() {
                    return Err(meta.error("duplicate `ctx` in `#[stable_abi_sample(...)]`"));
                }
                let expr = meta.value()?.parse::<Expr>()?;
                ctx_expr = Some(quote! { #expr });
                Ok(())
            } else {
                Err(meta.error(
                    "unsupported `stable_abi_sample` option; expected `with = \"...\"` or `ctx = <expr>`",
                ))
            }
        })?;
    }
    if with_expr.is_some() && ctx_expr.is_some() {
        return Err(Error::new_spanned(
            field,
            "cannot combine `with` and `ctx` in `#[stable_abi_sample(...)]`",
        ));
    }
    Ok(StableAbiSampleOptions {
        with_expr,
        ctx_expr,
    })
}

#[cfg(feature = "frozen-abi")]
fn stable_abi_sample_field_expr(field: &syn::Field) -> Result<TokenStream2, Error> {
    let options = parse_stable_abi_sample_options(field)?;
    let ty = &field.ty;
    Ok(match (options.with_expr, options.ctx_expr) {
        (Some(expr), None) => expr,
        (None, Some(ctx_expr)) => quote! {
            <#ty as ::solana_frozen_abi::stable_abi::StableAbi<_>>::random_with_context(
                rng,
                #ctx_expr,
            )
        },
        (None, None) => {
            quote! {
                <#ty as ::solana_frozen_abi::stable_abi::StableAbi>::random(rng)
            }
        }
        (Some(_), Some(_)) => unreachable!("`with` and `ctx` are mutually exclusive"),
    })
}

#[cfg(feature = "frozen-abi")]
fn add_stable_abi_type_param_bounds(mut generics: syn::Generics) -> syn::Generics {
    generics.type_params_mut().for_each(|type_param| {
        type_param.bounds.push(syn::parse_quote!(
            ::solana_frozen_abi::stable_abi::StableAbi
        ));
    });
    generics
}

#[cfg(feature = "frozen-abi")]
fn derive_stable_abi_sample_struct_type(input: ItemStruct) -> Result<TokenStream2, Error> {
    let type_name = &input.ident;
    let generics = add_stable_abi_type_param_bounds(input.generics);

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let turbofish = ty_generics.as_turbofish();
    let sample_expr = match &input.fields {
        Fields::Named(named_fields) => {
            let fields = named_fields
                .named
                .iter()
                .map(|field| -> Result<_, Error> {
                    let field_name = &field.ident;
                    let field_expr = stable_abi_sample_field_expr(field)?;
                    Ok(quote! {#field_name: #field_expr,})
                })
                .collect::<Result<Vec<_>, _>>()?;
            quote! {#type_name #turbofish { #(#fields)* }}
        }
        Fields::Unnamed(unnamed_fields) => {
            let fields = unnamed_fields
                .unnamed
                .iter()
                .map(stable_abi_sample_field_expr)
                .collect::<Result<Vec<_>, _>>()?;
            quote! {#type_name #turbofish ( #(#fields),* )}
        }
        Fields::Unit => quote! {#type_name #turbofish},
    };
    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::solana_frozen_abi::rand::distr::Distribution<#type_name #ty_generics>
            for ::solana_frozen_abi::rand::distr::StandardUniform
            #where_clause
        {
            fn sample<R: ::solana_frozen_abi::rand::Rng + ?Sized>(
                &self,
                rng: &mut R,
            ) -> #type_name #ty_generics {
                #sample_expr
            }
        }
    })
}

#[cfg(feature = "frozen-abi")]
fn stable_abi_sample_enum_variant_expr(
    type_name: &Ident,
    ty_generics: &syn::TypeGenerics,
    variant: &Variant,
) -> Result<TokenStream2, Error> {
    let variant_name = &variant.ident;
    let turbofish = ty_generics.as_turbofish();
    match &variant.fields {
        Fields::Unit => Ok(quote! {#type_name #turbofish::#variant_name}),
        Fields::Named(variant_fields) => {
            let fields = variant_fields
                .named
                .iter()
                .map(|field| -> Result<_, Error> {
                    let field_name = &field.ident;
                    let field_expr = stable_abi_sample_field_expr(field)?;
                    Ok(quote! {#field_name: #field_expr,})
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(quote! {#type_name #turbofish::#variant_name { #(#fields)* }})
        }
        Fields::Unnamed(variant_fields) => {
            let fields = variant_fields
                .unnamed
                .iter()
                .map(stable_abi_sample_field_expr)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(quote! {#type_name #turbofish::#variant_name( #(#fields),* )})
        }
    }
}

#[cfg(feature = "frozen-abi")]
fn derive_stable_abi_sample_enum_type(input: ItemEnum) -> Result<TokenStream2, Error> {
    let type_name = &input.ident;
    let variants = &input.variants;
    let generics = add_stable_abi_type_param_bounds(input.generics);

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let variant_count = variants.len();
    let match_arms = variants
        .iter()
        .enumerate()
        .map(|(index, variant)| -> Result<_, Error> {
            let sample_expr =
                stable_abi_sample_enum_variant_expr(type_name, &ty_generics, variant)?;
            Ok(quote! {#index => #sample_expr})
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::solana_frozen_abi::rand::distr::Distribution<#type_name #ty_generics>
            for ::solana_frozen_abi::rand::distr::StandardUniform
            #where_clause
        {
            fn sample<R: ::solana_frozen_abi::rand::Rng + ?Sized>(
                &self,
                rng: &mut R,
            ) -> #type_name #ty_generics {
                match rng.random_range(0..#variant_count) {
                    #(#match_arms,)*
                    _ => unreachable!(),
                }
            }
        }
    })
}

#[cfg(feature = "frozen-abi")]
fn derive_abi_sample_enum_type(input: ItemEnum) -> TokenStream {
    let type_name = &input.ident;

    let mut sample_variant = quote! {};
    let mut sample_variant_found = false;

    for variant in &input.variants {
        let variant_name = &variant.ident;
        let variant = &variant.fields;
        if *variant == Fields::Unit {
            sample_variant.extend(quote! {
                #type_name::#variant_name
            });
        } else if let Fields::Unnamed(variant_fields) = variant {
            let mut fields = quote! {};
            for field in &variant_fields.unnamed {
                if !(field.ident.is_none() && field.colon_token.is_none()) {
                    unimplemented!("tuple enum: {:?}", field);
                }
                let field_type = &field.ty;
                fields.extend(quote! {
                    <#field_type>::example(),
                });
            }
            sample_variant.extend(quote! {
                #type_name::#variant_name(#fields)
            });
        } else if let Fields::Named(variant_fields) = variant {
            let mut fields = quote! {};
            for field in &variant_fields.named {
                if field.ident.is_none() || field.colon_token.is_none() {
                    unimplemented!("tuple enum: {:?}", field);
                }
                let field_type = &field.ty;
                let field_name = &field.ident;
                fields.extend(quote! {
                    #field_name: <#field_type>::example(),
                });
            }
            sample_variant.extend(quote! {
                #type_name::#variant_name{#fields}
            });
        } else {
            unimplemented!("{:?}", variant);
        }

        if !sample_variant_found {
            sample_variant_found = true;
            break;
        }
    }

    if !sample_variant_found {
        unimplemented!("empty enum");
    }

    let mut attrs = input.attrs.clone();
    filter_allow_attrs(&mut attrs);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let result = quote! {
        #[automatically_derived]
        #( #attrs )*
        impl #impl_generics ::solana_frozen_abi::abi_example::AbiExample for #type_name #ty_generics #where_clause {
            fn example() -> Self {
                ::std::println!(
                    "AbiExample for enum: {}",
                    std::any::type_name::<#type_name #ty_generics>()
                );
                #sample_variant
            }
        }
    };
    result.into()
}

#[cfg(feature = "frozen-abi")]
fn derive_abi_sample_struct_type(input: ItemStruct) -> TokenStream {
    let type_name = &input.ident;
    let fields = &input.fields;
    let mut sample_fields = quote! {};

    match fields {
        Fields::Named(_) => {
            for field in fields {
                let field_name = &field.ident;
                sample_fields.extend(quote! {
                    #field_name: AbiExample::example(),
                });
            }
            sample_fields = quote! {{ #sample_fields }};
        }
        Fields::Unnamed(_) => {
            for _ in fields {
                sample_fields.extend(quote! {
                    AbiExample::example(),
                });
            }
            sample_fields = quote! {( #sample_fields )};
        }
        _ => unimplemented!("fields: {:?}", fields),
    }

    let mut attrs = input.attrs.clone();
    filter_allow_attrs(&mut attrs);
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let turbofish = ty_generics.as_turbofish();

    let result = quote! {
        #[automatically_derived]
        #( #attrs )*
        impl #impl_generics ::solana_frozen_abi::abi_example::AbiExample for #type_name #ty_generics #where_clause {
            fn example() -> Self {
                ::std::println!(
                    "AbiExample::example for struct: {}",
                    std::any::type_name::<#type_name #ty_generics>()
                );
                use ::solana_frozen_abi::abi_example::AbiExample;

                #type_name #turbofish #sample_fields
            }
        }
    };

    result.into()
}

#[cfg(feature = "frozen-abi")]
#[proc_macro_derive(AbiExample)]
pub fn derive_abi_sample(item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as Item);

    match item {
        Item::Struct(input) => derive_abi_sample_struct_type(input),
        Item::Enum(input) => derive_abi_sample_enum_type(input),
        _ => Error::new_spanned(item, "AbiSample isn't applicable; only for struct and enum")
            .to_compile_error()
            .into(),
    }
}

#[cfg(feature = "frozen-abi")]
fn do_derive_abi_enum_visitor(input: ItemEnum) -> TokenStream {
    let type_name = &input.ident;
    let mut serialized_variants = quote! {};
    let mut variant_count: u64 = 0;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    for variant in &input.variants {
        // Don't digest a variant with serde(skip)
        if filter_serde_attrs(&variant.attrs) {
            continue;
        };
        let sample_variant = quote_sample_variant(type_name, &ty_generics, variant);
        variant_count = if let Some(variant_count) = variant_count.checked_add(1) {
            variant_count
        } else {
            break;
        };
        serialized_variants.extend(quote! {
            #sample_variant;
            Serialize::serialize(&sample_variant, digester.create_enum_child()?)?;
        });
    }

    let type_str = format!("{type_name}");
    (quote! {
        impl #impl_generics ::solana_frozen_abi::abi_example::AbiEnumVisitor for #type_name #ty_generics #where_clause {
            fn visit_for_abi(&self, digester: &mut ::solana_frozen_abi::abi_digester::AbiDigester) -> ::solana_frozen_abi::abi_digester::DigestResult {
                let enum_name = #type_str;
                use ::serde::ser::Serialize;
                use ::solana_frozen_abi::abi_example::AbiExample;
                digester.update_with_string(::std::format!("enum {} (variants = {})", enum_name, #variant_count));
                #serialized_variants
                digester.create_child()
            }
        }
    }).into()
}

#[cfg(feature = "frozen-abi")]
#[proc_macro_derive(AbiEnumVisitor)]
pub fn derive_abi_enum_visitor(item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as Item);

    match item {
        Item::Enum(input) => do_derive_abi_enum_visitor(input),
        _ => Error::new_spanned(item, "AbiEnumVisitor not applicable; only for enum")
            .to_compile_error()
            .into(),
    }
}

#[cfg(feature = "frozen-abi")]
fn quote_for_test(
    test_mod_ident: &Ident,
    type_name: &Ident,
    expected_api_digest: Option<&Expr>,
    expected_abi_digest: Option<&Expr>,
    abi_serializers: &[AbiSerializer],
    roundtrip_test: RoundtripTest,
) -> TokenStream2 {
    let test_api = if let Some(expected_api_digest) = expected_api_digest {
        quote! {
                #[test]
                fn test_api_digest() {
                    use ::solana_frozen_abi::abi_example::{AbiExample, AbiEnumVisitor};

                    let mut digester = ::solana_frozen_abi::abi_digester::AbiDigester::create();
                    let example = <#type_name>::example();
                    let result = <_>::visit_for_abi(&&example, &mut digester);
                    let mut hash = digester.finalize();
                    if result.is_err() {
                        ::std::eprintln!("Error: digest error: {:#?}", result);
                    }
                    result.unwrap();
                    let actual_digest = ::std::format!("{}", hash);
                    if ::std::env::var("SOLANA_ABI_BULK_UPDATE").is_ok() {
                        if #expected_api_digest != actual_digest {
                            ::std::eprintln!("sed -i -e 's/{}/{}/g' $(git grep --files-with-matches frozen_abi)", #expected_api_digest, hash);
                        }
                        ::std::eprintln!("Warning: Not testing the abi digest under SOLANA_ABI_BULK_UPDATE!");
                    } else {
                        if let Ok(dir) = ::std::env::var("SOLANA_ABI_DUMP_DIR") {
                            assert_eq!(#expected_api_digest, actual_digest, "Possibly API changed? Examine the diff in SOLANA_ABI_DUMP_DIR!: \n$ diff -u {}/*{}* {}/*{}*", dir, #expected_api_digest, dir, actual_digest);
                        } else {
                            assert_eq!(#expected_api_digest, actual_digest, "Possibly API changed? Confirm the diff by rerunning before and after this test failed with SOLANA_ABI_DUMP_DIR!");
                        }
                    }
                }
        }
    } else {
        TokenStream2::new()
    };

    // Both serializers share the same expected digest, so generate a separate
    // test per serializer (named with the serializer) that each check against
    // it; the tests run in sequence without cross-checking each other.
    let test_abi = if let Some(expected_abi_digest) = expected_abi_digest {
        let abi_tests = abi_serializers.iter().map(|abi_serializer| {
            let test_fn_name = Ident::new(
                &format!("test_abi_digest_{}", abi_serializer.name()),
                Span::call_site(),
            );
            let abi_serialize_expr = abi_serializer.serialize_expr();
            let test_roundtrip = match roundtrip_test {
                RoundtripTest::No => TokenStream2::new(),
                RoundtripTest::WireOnly | RoundtripTest::EqAndWire => {
                    let test_roundtrip_eq = match roundtrip_test {
                        RoundtripTest::EqAndWire => quote! {
                            assert!(
                                val == roundtrip_val,
                                "deserializing serialized {} should preserve value",
                                roundtrip_type_name
                            );
                        },
                        _ => TokenStream2::new(),
                    };
                    quote! {
                        let roundtrip_type_name = ::std::any::type_name::<#type_name>();
                        let roundtrip_val: #type_name =
                            #abi_serialize_expr::deserialize::<#type_name>(&bytes).expect(
                                ::std::concat!(
                                    "must deserialize serialized ",
                                    ::std::stringify!(#type_name)
                                )
                            );

                        #test_roundtrip_eq

                        let roundtrip_bytes = #abi_serialize_expr::serialize(&roundtrip_val).expect(
                            ::std::concat!(
                                "must re-serialize ",
                                ::std::stringify!(#type_name)
                            )
                        );
                        assert_eq!(
                            bytes,
                            roundtrip_bytes,
                            "re-serializing deserialized {} should match bytes",
                            roundtrip_type_name
                        );
                    }
                }
            };
            quote! {
                #[test]
                fn #test_fn_name() {
                    use ::solana_frozen_abi::rand::{SeedableRng, RngCore};
                    use ::solana_frozen_abi::rand_chacha::ChaCha8Rng;
                    use ::solana_frozen_abi::stable_abi::StableAbi;

                    let mut rng = ChaCha8Rng::seed_from_u64(20666175621446498);
                    let mut digester = ::solana_frozen_abi::hash::Hasher::default();

                    for _ in 0..10_000 {
                        let val = <#type_name>::random(&mut rng);
                        let bytes = #abi_serialize_expr::serialize(&val)
                            .expect("must serialize");

                        #test_roundtrip

                        digester.hash(&bytes);
                    }
                    assert_eq!(#expected_abi_digest, ::std::format!("{}", digester.result()), "ABI layout has changed!");
                }
            }
        });
        quote! { #(#abi_tests)* }
    } else {
        TokenStream2::new()
    };

    quote! {
        #[cfg(test)]
        mod #test_mod_ident {
            use super::*;
            #test_api
            #test_abi
        }
    }
}

#[cfg(feature = "frozen-abi")]
fn test_mod_name(type_name: &Ident) -> Ident {
    Ident::new(&format!("{type_name}_frozen_abi"), Span::call_site())
}

#[cfg(feature = "frozen-abi")]
fn frozen_abi_type_alias(
    input: ItemType,
    expected_api_digest: Option<&Expr>,
    expected_abi_digest: Option<&Expr>,
    abi_serializers: &[AbiSerializer],
    roundtrip_test: RoundtripTest,
) -> TokenStream {
    let type_name = &input.ident;
    let test = quote_for_test(
        &test_mod_name(type_name),
        type_name,
        expected_api_digest,
        expected_abi_digest,
        abi_serializers,
        roundtrip_test,
    );
    let result = quote! {
        #input
        #test
    };
    result.into()
}

#[cfg(feature = "frozen-abi")]
fn frozen_abi_struct_type(
    input: ItemStruct,
    expected_api_digest: Option<&Expr>,
    expected_abi_digest: Option<&Expr>,
    abi_serializers: &[AbiSerializer],
    roundtrip_test: RoundtripTest,
) -> TokenStream {
    let type_name = &input.ident;
    let test = quote_for_test(
        &test_mod_name(type_name),
        type_name,
        expected_api_digest,
        expected_abi_digest,
        abi_serializers,
        roundtrip_test,
    );
    let result = quote! {
        #input
        #test
    };
    result.into()
}

#[cfg(feature = "frozen-abi")]
fn quote_sample_variant(
    type_name: &Ident,
    ty_generics: &syn::TypeGenerics,
    variant: &Variant,
) -> TokenStream2 {
    let variant_name = &variant.ident;
    let variant = &variant.fields;
    if *variant == Fields::Unit {
        quote! {
            let sample_variant: #type_name #ty_generics = #type_name::#variant_name;
        }
    } else if let Fields::Unnamed(variant_fields) = variant {
        let mut fields = quote! {};
        for field in &variant_fields.unnamed {
            if !(field.ident.is_none() && field.colon_token.is_none()) {
                unimplemented!();
            }
            let ty = &field.ty;
            fields.extend(quote! {
                <#ty>::example(),
            });
        }
        quote! {
            let sample_variant: #type_name #ty_generics = #type_name::#variant_name(#fields);
        }
    } else if let Fields::Named(variant_fields) = variant {
        let mut fields = quote! {};
        for field in &variant_fields.named {
            if field.ident.is_none() || field.colon_token.is_none() {
                unimplemented!();
            }
            let field_type_name = &field.ty;
            let field_name = &field.ident;
            fields.extend(quote! {
                #field_name: <#field_type_name>::example(),
            });
        }
        quote! {
            let sample_variant: #type_name #ty_generics = #type_name::#variant_name{#fields};
        }
    } else {
        unimplemented!("variant: {:?}", variant)
    }
}

#[cfg(feature = "frozen-abi")]
fn frozen_abi_enum_type(
    input: ItemEnum,
    expected_api_digest: Option<&Expr>,
    expected_abi_digest: Option<&Expr>,
    abi_serializers: &[AbiSerializer],
    roundtrip_test: RoundtripTest,
) -> TokenStream {
    let type_name = &input.ident;
    let test = quote_for_test(
        &test_mod_name(type_name),
        type_name,
        expected_api_digest,
        expected_abi_digest,
        abi_serializers,
        roundtrip_test,
    );
    let result = quote! {
        #input
        #test
    };
    result.into()
}

#[cfg(feature = "frozen-abi")]
#[proc_macro_attribute]
pub fn frozen_abi(attrs: TokenStream, item: TokenStream) -> TokenStream {
    let mut api_expected_digest: Option<Expr> = None;
    let mut abi_expected_digest: Option<Expr> = None;
    let mut abi_serializers = vec![AbiSerializer::Bincode];
    let mut test_roundtrip: Option<LitStr> = None;

    let attrs_parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("digest") || meta.path.is_ident("api_digest") {
            api_expected_digest = Some(meta.value()?.parse::<Expr>()?);
            Ok(())
        } else if meta.path.is_ident("abi_digest") {
            abi_expected_digest = Some(meta.value()?.parse::<Expr>()?);
            Ok(())
        } else if meta.path.is_ident("abi_serializer") {
            abi_serializers = parse_abi_serializers(&meta.value()?.parse::<Expr>()?)?;
            Ok(())
        } else if meta.path.is_ident("test_roundtrip") {
            test_roundtrip = Some(meta.value()?.parse::<LitStr>()?);
            Ok(())
        } else {
            Err(meta.error("unsupported \"frozen_abi\" property"))
        }
    });
    parse_macro_input!(attrs with attrs_parser);

    if api_expected_digest.is_none() && abi_expected_digest.is_none() {
        return Error::new_spanned(
            TokenStream2::from(item),
            "missing required attribute: #[frozen_abi(api_digest = \"...\" or abi_digest = \"...\")]",
        )
        .to_compile_error()
        .into();
    }

    let roundtrip_test = match parse_roundtrip_test(test_roundtrip.as_ref()) {
        Ok(roundtrip_test) => roundtrip_test,
        Err(error) => return error.to_compile_error().into(),
    };

    let item = parse_macro_input!(item as Item);
    match item {
        Item::Struct(input) => frozen_abi_struct_type(
            input,
            api_expected_digest.as_ref(),
            abi_expected_digest.as_ref(),
            &abi_serializers,
            roundtrip_test,
        ),
        Item::Enum(input) => frozen_abi_enum_type(
            input,
            api_expected_digest.as_ref(),
            abi_expected_digest.as_ref(),
            &abi_serializers,
            roundtrip_test,
        ),
        Item::Type(input) => frozen_abi_type_alias(
            input,
            api_expected_digest.as_ref(),
            abi_expected_digest.as_ref(),
            &abi_serializers,
            roundtrip_test,
        ),
        _ => Error::new_spanned(
            item,
            "frozen_abi isn't applicable; only for struct, enum and type",
        )
        .to_compile_error()
        .into(),
    }
}

#[cfg(all(test, feature = "frozen-abi"))]
mod parse_abi_serializers_tests {
    use {
        super::*,
        AbiSerializer::{Bincode, Wincode},
    };

    /// Parse `input` as an expression.
    fn expr(input: &str) -> Expr {
        syn::parse_str(input).unwrap()
    }

    #[test]
    fn valid_serializers() {
        assert_eq!(
            parse_abi_serializers(&expr(r#""bincode""#)).unwrap(),
            vec![Bincode]
        );
        assert_eq!(
            parse_abi_serializers(&expr(r#""wincode""#)).unwrap(),
            vec![Wincode]
        );
        assert_eq!(
            parse_abi_serializers(&expr(r#"["wincode"]"#)).unwrap(),
            vec![Wincode]
        );
        assert_eq!(
            parse_abi_serializers(&expr(r#"["bincode", "wincode"]"#)).unwrap(),
            vec![Bincode, Wincode]
        );
        // Order is preserved and duplicates are kept as-is.
        assert_eq!(
            parse_abi_serializers(&expr(r#"["wincode", "bincode", "wincode"]"#)).unwrap(),
            vec![Wincode, Bincode, Wincode]
        );
    }

    #[test]
    fn invalid_serializers_are_rejected() {
        let err = |input| parse_abi_serializers(&expr(input)).unwrap_err().to_string();

        // Empty list.
        assert!(err(r#"[]"#).contains("must not be empty"));

        // Unsupported value, standalone and inside a list.
        assert!(err(r#""json""#).contains("unsupported"));
        assert!(err(r#""json""#).contains("json"));
        assert!(err(r#"["bincode", "json"]"#).contains("unsupported"));

        // Non-string literal, standalone and inside a list.
        assert!(err(r#"42"#).contains("expected a string literal"));
        assert!(err(r#"["bincode", 42]"#).contains("expected a string literal"));
    }

    #[test]
    fn group_wrapped_literal_is_unwrapped() {
        // A `macro_rules!` `:literal` fragment is interpolated into the
        // attribute wrapped in an invisible `Group`. Build such an expression
        // directly to ensure `parse_abi_serializers` unwraps it.
        let group = proc_macro2::Group::new(
            proc_macro2::Delimiter::None,
            expr(r#""wincode""#).to_token_stream(),
        );
        let grouped: Expr = syn::parse2(group.to_token_stream()).unwrap();
        assert!(matches!(grouped, Expr::Group(_)), "expected a grouped expr");
        assert_eq!(parse_abi_serializers(&grouped).unwrap(), vec![Wincode]);
    }
}
