interface SwitchProps {
  checked: boolean;
  disabled?: boolean;
  label: string;
  onChange: () => void;
}

export function Switch(props: SwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={props.checked ? "true" : "false"}
      aria-label={props.label}
      disabled={props.disabled}
      onClick={props.onChange}
      class="c-switch cursor-pointer"
    />
  );
}
