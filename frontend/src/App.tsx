import { Container, Title, Paper, Button, Select, Text, Center, Stack, Loader } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useState, useEffect } from 'react';

function App() {
  const [submitted, setSubmitted] = useState(false);
  const [ip, setIp] = useState<string | null>(null);
  const [loadingIp, setLoadingIp] = useState(true);

  const form = useForm({
    initialValues: {
      duration: '60',
    },
  });

  useEffect(() => {
    fetch('/ip')
      .then(res => res.json())
      .then(data => {
        setIp(data.ip);
        setLoadingIp(false);
      })
      .catch(err => {
        console.error('Failed to fetch IP', err);
        setIp('Unknown');
        setLoadingIp(false);
      });
  }, []);

  const handleSubmit = (values: typeof form.values) => {
    setSubmitted(true);

    fetch('/whitelist', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ duration: values.duration }),
    })
      .then(res => {
        if (!res.ok) throw new Error('Network response was not ok');
        return res.json();
      })
      .then(data => {
        console.log('Success:', data);
        // Success message is shown by `submitted` state,
        // strictly speaking we should have a separate success state,
        // but for now we keep `submitted` as true to show the message.
        // We'll reset it after a delay to allow re-submission.
        setTimeout(() => setSubmitted(false), 5000);
      })
      .catch(error => {
        console.error('Error:', error);
        setSubmitted(false);
        // In a real app, show error notification
        alert('Failed to whitelist IP');
      });
  };

  return (
    <Center h="100vh" bg="gray.1">
      <Container size="xs" w="100%">
        <Paper shadow="md" p="xl" radius="md" withBorder>
          <Stack gap="lg">
            <div style={{ textAlign: 'center' }}>
              <Title order={2}>Cloudflare IP Whitelist</Title>
              <Text c="dimmed" size="sm" mt={4}>
                Temporarily allow access to your current IP
              </Text>
              <Text size="md" fw={500} mt={10}>
                {loadingIp ? <Loader size="xs" type="dots" /> : `Your IP: ${ip}`}
              </Text>
            </div>

            <form onSubmit={form.onSubmit(handleSubmit)}>
              <Stack gap="md">
                <Select
                  label="Duration"
                  placeholder="Select duration"
                  data={[
                    { value: '60', label: '1 Hour' },
                    { value: '240', label: '4 Hours' },
                    { value: '480', label: '8 Hours' },
                    { value: '1440', label: '24 Hours' },
                  ]}
                  {...form.getInputProps('duration')}
                />

                <Button type="submit" fullWidth loading={submitted} mt="md">
                  Whitelist IP
                </Button>

                {submitted && (
                  <Text c="green" size="sm" ta="center">
                    Request sent successfully!
                  </Text>
                )}
              </Stack>
            </form>
          </Stack>
        </Paper>
      </Container>
    </Center>
  );
}

export default App;
