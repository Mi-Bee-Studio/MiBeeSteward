// Ambient declarations for 'd3-force-3d' (#703): the package ships no types
// and has no @types counterpart. The 3D simulation API is a superset of
// d3-force's (same call signatures, plus a z axis this canvas doesn't use
// through these imports), so the used surface re-exports the well-typed
// @types/d3-force models. Call sites already narrow node/link types with
// `as never` at the boundary.
declare module 'd3-force-3d' {
	export * from 'd3-force';
}
