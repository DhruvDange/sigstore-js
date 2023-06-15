// Returns a type that is a copy of the given object with the specified keys
// made required.
export type WithRequired<T, K extends keyof T> = T & {
  [P in K]-?: NonNullable<T[P]>;
};
