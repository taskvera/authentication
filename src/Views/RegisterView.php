<?php
$error = $_GET['error'] ?? '';
if (!empty($error)) {
    $safeError = htmlspecialchars($error, ENT_QUOTES, 'UTF-8');
    echo "
    <div class='bg-red-100 text-red-700 border-l-4 border-red-500 p-3 mb-4'>
      <strong>Error:</strong> {$safeError}
    </div>";
}
?>

<form action="/register" method="POST" class="max-w-sm mx-auto mt-8">
  <h2 class="text-xl font-bold mb-4">Create Account</h2>

  <!-- Tenant could be identified by slug or numeric ID -->
  <input type="hidden" name="tenant_id" value="<?= htmlspecialchars($_GET['tenant'] ?? 'default') ?>">

  <label for="email" class="block mb-1">Email</label>
  <input
    type="email"
    id="email"
    name="email"
    class="w-full border px-2 py-1 mb-4"
    required
  />

  <label for="password" class="block mb-1">Password</label>
  <input
    type="password"
    id="password"
    name="password"
    class="w-full border px-2 py-1 mb-4"
    required
  />

  <button
    type="submit"
    class="bg-blue-600 text-white px-4 py-2 rounded"
  >
    Register
  </button>
</form>
