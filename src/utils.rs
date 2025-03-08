use std::{mem, ops::Range};

pub fn elem_offset<T>(slice: &[T], element: &T) -> Option<usize> {
    // TODO: replace this once https://github.com/rust-lang/rust/issues/76393 becomes stable.
    if mem::size_of::<T>() == 0 {
        panic!("elements are zero-sized");
    }

    let self_start = slice.as_ptr() as usize;
    let elem_start = element as *const T as usize;

    let byte_offset = elem_start.wrapping_sub(self_start);

    if byte_offset % mem::size_of::<T>() != 0 {
        return None;
    }

    let offset = byte_offset / mem::size_of::<T>();

    if offset < slice.len() {
        Some(offset)
    } else {
        None
    }
}

pub fn subslice_range<T>(slice: &[T], subslice: &[T]) -> Option<Range<usize>> {
    // TODO: replace this once https://github.com/rust-lang/rust/issues/76393 becomes stable.
    if mem::size_of::<T>() == 0 {
        panic!("elements are zero-sized");
    }

    let self_start = slice.as_ptr() as usize;
    let subslice_start = subslice.as_ptr() as usize;

    let byte_start = subslice_start.wrapping_sub(self_start);

    if byte_start % core::mem::size_of::<T>() != 0 {
        return None;
    }

    let start = byte_start / core::mem::size_of::<T>();
    let end = start.wrapping_add(subslice.len());

    if start <= slice.len() && end <= slice.len() {
        Some(start..end)
    } else {
        None
    }
}
