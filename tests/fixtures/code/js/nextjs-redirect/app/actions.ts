"use server";

import { redirect } from "next/navigation";

export async function forward(target: string) {
  redirect(target);
}
