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
    use {
        quote::quote,
        syn::{parse_macro_input, Error, Item},
    };

    let item = parse_macro_input!(item as Item);
    let ident = match item {
        Item::Struct(ref s) => &s.ident,
        Item::Enum(ref e) => &e.ident,
        Item::Type(ref t) => &t.ident,
        _ => {
            return Error::new_spanned(
                item,
                "StableAbi can only be derived for struct, enum, or type alias",
            )
            .to_compile_error()
            .into();
        }
    };

    let expanded = quote! {
        #[automatically_derived]
        impl ::solana_frozen_abi::stable_abi::StableAbi for #ident {}
    };
    expanded.into()
}

#[cfg(feature = "frozen-abi")]
use proc_macro2::{Span, TokenStream as TokenStream2, TokenTree};
#[cfg(feature = "frozen-abi")]
use quote::{quote, ToTokens};
#[cfg(feature = "frozen-abi")]
use syn::{
    parse_macro_input, Attribute, Error, Fields, Ident, Item, ItemEnum, ItemStruct, ItemType,
    LitStr, Variant,
};

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
    expected_api_digest: &str,
    expected_abi_digest: Option<&str>,
) -> TokenStream2 {
    let test_api = quote! {
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
    };

    let test_abi = if expected_abi_digest.is_some() {
        quote! {
            #[test]
            fn test_abi_digest() {
                use ::solana_frozen_abi::rand::{SeedableRng, RngCore};
                use ::solana_frozen_abi::rand_chacha::ChaCha8Rng;
                use ::solana_frozen_abi::bincode;
                use ::solana_frozen_abi::stable_abi::StableAbi;

                let mut rng = ChaCha8Rng::seed_from_u64(20666175621446498);
                let mut digester = ::solana_frozen_abi::hash::Hasher::default();

                for _ in 0..10_000 {
                    let val = <#type_name>::random(&mut rng);
                    digester.hash(&bincode::serialize(&val).unwrap());
                }
                assert_eq!(#expected_abi_digest, ::std::format!("{}", digester.result()), "ABI layout has changed!");
            }
        }
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
    expected_api_digest: &str,
    expected_abi_digest: Option<&str>,
) -> TokenStream {
    let type_name = &input.ident;
    let test = quote_for_test(
        &test_mod_name(type_name),
        type_name,
        expected_api_digest,
        expected_abi_digest,
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
    expected_api_digest: &str,
    expected_abi_digest: Option<&str>,
) -> TokenStream {
    let type_name = &input.ident;
    let test = quote_for_test(
        &test_mod_name(type_name),
        type_name,
        expected_api_digest,
        expected_abi_digest,
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
    expected_api_digest: &str,
    expected_abi_digest: Option<&str>,
) -> TokenStream {
    let type_name = &input.ident;
    let test = quote_for_test(
        &test_mod_name(type_name),
        type_name,
        expected_api_digest,
        expected_abi_digest,
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
    let mut api_expected_digest: Option<String> = None;
    let mut abi_expected_digest: Option<String> = None;

    let attrs_parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("digest") || meta.path.is_ident("api_digest") {
            api_expected_digest = Some(meta.value()?.parse::<LitStr>()?.value());
            Ok(())
        } else if meta.path.is_ident("abi_digest") {
            abi_expected_digest = Some(meta.value()?.parse::<LitStr>()?.value());
            Ok(())
        } else {
            Err(meta.error("unsupported \"frozen_abi\" property"))
        }
    });
    parse_macro_input!(attrs with attrs_parser);

    let Some(api_expected_digest) = api_expected_digest else {
        return Error::new_spanned(
            TokenStream2::from(item),
            "missing required attribute: #[frozen_abi(api_digest = \"...\")]",
        )
        .to_compile_error()
        .into();
    };

    let item = parse_macro_input!(item as Item);
    match item {
        Item::Struct(input) => {
            frozen_abi_struct_type(input, &api_expected_digest, abi_expected_digest.as_deref())
        }
        Item::Enum(input) => {
            frozen_abi_enum_type(input, &api_expected_digest, abi_expected_digest.as_deref())
        }
        Item::Type(input) => {
            frozen_abi_type_alias(input, &api_expected_digest, abi_expected_digest.as_deref())
        }
        _ => Error::new_spanned(
            item,
            "frozen_abi isn't applicable; only for struct, enum and type",
        )
        .to_compile_error()
        .into(),
    }
}
