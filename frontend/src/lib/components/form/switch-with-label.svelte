<script lang="ts">
	import { Label } from '$lib/components/ui/label';
	import { Switch } from '$lib/components/ui/switch/index.js';
	import { cn } from '$lib/utils/style';
	import type { HTMLAttributes } from 'svelte/elements';

	let {
		id,
		checked = $bindable(),
		label,
		description,
		disabled = false,
		onCheckedChange,
		class: className
	}: {
		class?: HTMLAttributes<HTMLDivElement>['class'];
		id: string;
		checked: boolean;
		label: string;
		description?: string;
		disabled?: boolean;
		onCheckedChange?: (checked: boolean) => void;
	} = $props();
</script>

<div class={cn('grid w-full grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3', className)}>
	<Switch
		{id}
		{disabled}
		onCheckedChange={(v) => onCheckedChange && onCheckedChange(v == true)}
		bind:checked
	/>
	<div class="min-w-0 space-y-1.5 leading-none">
		<Label for={id} class="mb-0 text-sm leading-none font-medium">
			{label}
		</Label>
		{#if description}
			<p class="text-muted-foreground text-[0.8rem] leading-snug">
				{description}
			</p>
		{/if}
	</div>
</div>
